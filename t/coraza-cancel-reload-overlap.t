#!/usr/bin/perl

# Tests for Coraza-nginx connector: client cancellation and `nginx -s reload`
# overlapping an in-flight transaction.
#
# ngx_http_coraza_cleanup() (src/ngx_http_coraza_module.c) is registered on
# r->pool and is the only place coraza_free_transaction() is called; nginx
# runs pool cleanups exactly once when the request pool is destroyed,
# regardless of whether the request finished normally, was aborted by the
# client, or its worker is draining after a reload. So the oracle for "no
# double free / no WAF free-before-transaction" is: the worker does not
# crash (no SIGSEGV/ASan/UBSan mark in error.log) and, since a double-free or
# use-after-free inside libcoraza's transaction free path would either abort
# the process or corrupt the allocator that later requests depend on, the
# server must also go on to serve a completely unrelated follow-up request
# correctly afterward.
#
# Coverage:
#   (1) client cancellation mid deferred-request-body -- the client sends
#       part of the body then closes, so ngx_http_coraza_pre_access.c is
#       sitting in the NGX_AGAIN / waiting_more_body path when the pool is
#       destroyed.
#   (2) client cancellation mid delayed-response -- coraza_delay_response_headers
#       holds response headers back for a phase-4 rule while a slow upstream
#       body is in flight; the client closes before any byte of the response
#       reaches it, so cleanup runs with the transaction mid response-phase.
#   (3) `nginx -s reload` while a request is in flight, at three phases:
#       deferred request body, delayed response headers/body, and an
#       intervention (phase-4 deny). The reload sends the old worker
#       QUIT-on-drain (it keeps serving in-flight connections while the new
#       worker takes new ones), so the in-flight transaction's cleanup runs
#       during worker shutdown instead of during normal request completion.
#
# COVERAGE GAP: reload changes the pid nginx.pid records to the new worker's
# master-tracked pid immediately, but the OLD worker (the one whose pool
# cleanup we care about) keeps running until it drains. Test::Nginx's
# reload() only sends SIGHUP and returns; it has no hook to observe when the
# specific old worker PID that held our transaction has actually exited, so
# these tests cannot assert "the old worker's cleanup ran" as a directly
# observed event distinct from "the response came back correctly and the
# server kept working" -- they rely on the crash oracle plus the successful
# follow-up request as the closest available proxy. A tighter test would need
# a way to pin/observe the specific worker pid across the reload, which this
# harness does not expose.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(9);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
master_process on;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        # Deferred request body: no Content-Length is available at preread
        # time because the client sends the headers and a partial body then
        # stalls/closes, forcing ngx_http_coraza_pre_access.c into the
        # NGX_AGAIN / waiting_more_body branch.
        location /body {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Delayed response: phase-4 rule forces coraza_delay_response_headers
        # to hold the response until the upstream body (deliberately slow) is
        # in.  The transaction is alive and mid response-phase when the
        # client cancels.
        location /slow-response {
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq observe" "id:170,phase:4,pass,log"
            ';
            proxy_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Intervention target for the reload-during-intervention case: a
        # phase-4 deny that runs after headers were held.
        location /reload-intervention {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
                SecRule ARGS "@streq block" "id:171,phase:4,deny,log,status:403"
            ';
        }

        # Plain follow-up target used after every cancellation/reload case to
        # prove the worker is still healthy and serving new transactions
        # correctly -- the strongest available proxy for "exactly one
        # transaction cleanup ran and nothing corrupted the allocator".
        location /healthy {
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq attack" "id:172,phase:1,deny,status:403,log"
            ';
            return 200 "HEALTHY-OK";
        }
    }
}
EOF

my $testdir = $t->testdir();

$t->run_daemon(\&slow_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# --- (1) client cancellation mid deferred request body --------------------

{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    # Content-Length announces more body than we will ever send, so the
    # request stays in the deferred/waiting_more_body state until we close.
    print $s "POST /body HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: 65536" . CRLF . CRLF
        . "x=partial-and-never-finished";

    select undef, undef, undef, 0.2;
    close $s;
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker survives client cancel mid deferred request body '
    . '(single transaction cleanup, no crash)');

# --- (2) client cancellation mid delayed response --------------------------

{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /slow-response?q=observe HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    # Deterministic sync: the daemon writes a marker once it is blocked
    # holding the response body back, i.e. the coraza transaction is
    # definitely alive and mid response-phase server-side, before we cancel.
    wait_for_marker('slow-response-holding');
    close $s;
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker survives client cancel mid delayed response '
    . '(single transaction cleanup, no crash)');

# --- (3) reload overlapping an in-flight transaction ------------------------

# (3a) deferred request body in flight across a reload.
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "POST /body HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: 20" . CRLF . CRLF
        . "x=abc";

    select undef, undef, undef, 0.2;

    $t->reload();
    select undef, undef, undef, 0.5;

    print $s "defghijklmno";

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $reply = '';
    eval {
        alarm(8);
        local $/;
        $reply = $s->getline() // '';
        alarm(0);
    };
    alarm(0);
    close $s;

    like($reply, qr/^HTTP\S+ 200/,
        'in-flight deferred request body completes across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping deferred request body');

# (3b) delayed response headers/body in flight across a reload.
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /slow-response?q=observe HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    wait_for_marker('slow-response-holding');

    $t->reload();
    select undef, undef, undef, 0.5;

    release_marker('slow-response-release');

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $reply = '';
    eval {
        alarm(8);
        local $/;
        $reply = $s->getline() // '';
        alarm(0);
    };
    alarm(0);
    close $s;

    like($reply, qr/^HTTP\S+ 200.*SLOW-BODY-DONE/s,
        'in-flight delayed response completes across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping a delayed response');

# (3c) reload overlapping an intervention (phase-4 deny).
{
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /reload-intervention?q=block HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    # No deterministic marker is available for the intervention itself (it
    # runs synchronously inside the phase handler), so give the reload a
    # short, fixed window to land while the request is being processed. This
    # is best-effort ordering, not a proven overlap -- documented above.
    select undef, undef, undef, 0.05;
    $t->reload();

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $reply = '';
    eval {
        alarm(8);
        local $/;
        $reply = $s->getline() // '';
        alarm(0);
    };
    alarm(0);
    close $s;

    like($reply, qr/^HTTP\S+ 403/,
        'in-flight intervention still cleanly blocks across a reload');
}

like(http_get_healthy(), qr/HEALTHY-OK/,
    'worker healthy after reload overlapping an intervention');

# --- crash oracle ------------------------------------------------------------

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer|UndefinedBehaviorSanitizer|double free|invalid free/,
    'no crash or double-free signature across cancellation/reload overlap');

###############################################################################

sub http_get_healthy {
    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
    ) or die "Can't connect to nginx: $!\n";
    $s->autoflush(1);

    print $s "GET /healthy HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF . CRLF;

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $reply = '';
    eval {
        alarm(8);
        local $/;
        $reply = $s->getline() // '';
        alarm(0);
    };
    alarm(0);
    close $s;

    return $reply;
}

sub wait_for_marker {
    my ($name) = @_;
    my $marker = "$testdir/$name";

    for (1 .. 500) {
        return if -e $marker;
        select undef, undef, undef, 0.01;
    }

    die "timeout waiting for marker $marker\n";
}

sub release_marker {
    my ($name) = @_;

    open my $fh, '>', "$testdir/$name"
        or die "Can't write release marker: $!\n";
    print $fh "go\n";
    close $fh;
}

# A slow upstream: sends response headers immediately, then blocks holding the
# body back (writing a "holding" marker as soon as it starts blocking) until
# the "release" marker file appears, then finishes the body.  Used for
# /slow-response, which delays forwarding headers to the client behind a
# phase-4 rule -- the client sees nothing until the marker is released.
sub slow_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1:' . port(8081),
        Listen => 5,
        Reuse => 1
    ) or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $request = <$client>;
        if (!defined $request) {
            close $client;
            next;
        }

        my ($uri) = $request =~ /^\S+\s+(\S+)/;

        while (<$client>) {
            last if (/^\x0d?\x0a?$/);
        }

        if (defined $uri && $uri =~ m{^/body}) {
            print $client "HTTP/1.1 200 OK" . CRLF;
            print $client "Content-Length: 7" . CRLF;
            print $client "Connection: close" . CRLF . CRLF;
            print $client "BODY-OK";
            close $client;
            next;
        }

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Length: 14\r\n"
            . "Content-Type: text/plain\r\n\r\n";

        open my $fh, '>', "$testdir/slow-response-holding"
            or die "Can't write holding marker: $!\n";
        print $fh "holding\n";
        close $fh;

        my $release = "$testdir/slow-response-release";
        for (1 .. 800) {
            last if -e $release;
            select undef, undef, undef, 0.01;
        }

        print $client "SLOW-BODY-DONE";
        close $client;
    }
}

###############################################################################
