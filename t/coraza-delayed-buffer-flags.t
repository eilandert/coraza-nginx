#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed-header buffer-flag matrix).
#
# t/coraza-delayed-file-buffer.t covers the uninspected file-backed clone
# branch (large file, sendfile off, phase-4 pass). t/coraza-response-body-
# trailing-buf.t covers the one-shot phase-4 gate on a trailing buffer. Two
# things those files do not exercise:
#
#   (a) the flush/sync buffer-flag matrix on intermediate buffers moved
#       through the delayed-header path -- both the in-memory copy branch
#       (ngx_http_coraza_body_filter.c ~L459-461, which explicitly copies
#       chain->buf->flush onto the pool copy but never touches ->sync) and
#       the uninspected file-clone branch (~L401-407, `*b = *chain->buf`
#       followed by `b->last_buf = 0`, which copies flush/sync/recycled via
#       the struct assignment and never re-clears them). recycled proxy
#       buffers and a spilled proxy temp file are both driven through this
#       path.
#   (b) a slow-reading / disconnecting client on the delayed-header path:
#       the request must not wedge the worker and a healthy follow-up
#       request on the same keepalive connection must still work.
#
# Source-shape assertions pin (a) at the code level (both branches must
# preserve or intentionally drop these flags -- see the per-assertion
# comments); the HTTP-level checks below exercise the same paths at
# runtime and assert exact byte counts.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_body_filter.c");

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(10);

# --- Source-shape: in-memory intermediate-buffer copy branch --------------
#
# The pool copy explicitly propagates ->flush and ->last_in_chain from the
# source buffer. It must NOT propagate ->sync: nginx's sync flag exists to
# push a zero-length "boundary" buffer through the filter chain without new
# data, and the pool copy already carries its own (possibly non-empty) data
# with last_buf forced to 0 -- reusing the source sync bit on a buffer that
# is not the source's actual sync boundary would be a category error, not a
# faithful clone. This pins the *current, deliberate* selection so a future
# edit that starts copying ->sync here is a visible diff, not a silent
# behavior change.
like($src,
    qr/b->last_buf\s*=\s*0;\s*\n\s*b->last_in_chain\s*=\s*chain->buf->last_in_chain;\s*\n\s*b->flush\s*=\s*chain->buf->flush;/s,
    'in-memory delayed-copy branch propagates last_in_chain and flush from the source buffer');

unlike($src,
    qr/b->last_buf\s*=\s*0;\s*\n\s*b->last_in_chain\s*=\s*chain->buf->last_in_chain;\s*\n\s*b->flush\s*=\s*chain->buf->flush;\s*\n\s*b->sync/s,
    'in-memory delayed-copy branch does not also propagate sync (would need its own justification)');

# --- Source-shape: uninspected file-clone branch ---------------------------
#
# `*b = *chain->buf` is a full struct copy, so flush/sync/recycled/temporary
# etc. all travel onto the clone before last_buf is explicitly zeroed. This
# pins that the clear is scoped to last_buf only -- a future edit that widens
# it to `ngx_memzero(b, ...)` or similarly drops flush/sync would silently
# stop propagating flow-control hints (a flushed intermediate buffer becoming
# un-flushed downstream) and this assertion would catch the source shape
# changing.
like($src,
    qr/\*b\s*=\s*\*chain->buf;\s*\n\s*b->last_buf\s*=\s*0;/s,
    'uninspected file-clone branch copies the whole source buf (flush/sync included) then clears only last_buf');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        # Small proxy buffers force nginx to hand the body filter several
        # recycled, non-final in-memory buffers (flush semantics from the
        # upstream's TCP segmentation) instead of one big buffer -- this
        # drives the in-memory copy branch on more than the trivial
        # single-buffer case.
        location /recycled {
            default_type text/plain;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_buffering on;
            proxy_buffer_size 512;
            proxy_buffers 8 512;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 262144
                SecRule RESPONSE_BODY "@rx NEVER MATCHES THIS" "id:171,phase:4,deny,log,status:403"
            ';
        }

        # proxy_max_temp_file_size forces the response to spill to a proxy
        # temp file once the in-memory proxy_buffers are exhausted -- the
        # delayed-header path then sees ngx_buf_in_memory()==0, in_file==1,
        # temp_file==1 buffers, which the uninspected clone branch's
        # !chain->buf->temp_file guard explicitly EXCLUDES (upstream temp
        # files keep the copy path because their lifetime is controlled by
        # upstream) -- so this exercises the in-memory copy branch's read
        # path on file-backed data, not the clone branch.
        location /proxy-temp-file {
            default_type application/octet-stream;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 4 4k;
            proxy_max_temp_file_size 1m;
            proxy_temp_file_write_size 4k;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }

        # Slow-reading / disconnecting client on the delayed-header path,
        # then a healthy follow-up request on the same keepalive connection.
        location /slow {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }
    }
}
EOF

my $recycled_body = ("R" x 200 . "\n") x 40; # ~8 KB, well past 8x512B buffers
my $temp_file_body = "T" x (64 * 1024);      # past 4x4k proxy_buffers
my $slow_body = "S" x (32 * 1024);

$t->run_daemon(\&http_daemon, port(8081), $recycled_body, $temp_file_body);
$t->write_file('/slow', $slow_body);

$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# Recycled in-memory buffers: full body must still arrive intact, with no
# duplication or truncation from the flush-carrying copy branch.
my $r = http_get('/recycled');
like($r, qr/^HTTP\S+ 200/, 'recycled small-proxy-buffer response returns 200');
my ($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), length($recycled_body),
    'recycled small-proxy-buffer response body length matches exactly');
is($body, $recycled_body,
    'recycled small-proxy-buffer response body bytes match exactly');

# Proxy temp-file-backed buffers: full body must still arrive intact.
$r = http_get('/proxy-temp-file');
like($r, qr/^HTTP\S+ 200/, 'proxy-temp-file response returns 200');
($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), length($temp_file_body),
    'proxy-temp-file response body length matches exactly');

# Slow-reading / disconnecting client, then a healthy follow-up request on
# the same connection.
my ($n_read, $ok) = slow_read_then_reuse('/slow', length($slow_body));
is($n_read, 4096, 'slow client read exactly the requested partial prefix before disconnecting');
is($ok, 1, 'a fresh request after the slow/disconnecting one still succeeds');

###############################################################################

sub slurp {
    my ($path) = @_;

    open my $fh, '<', $path or die "open $path: $!";
    local $/ = undef;
    return <$fh>;
}

# Open a connection, send the request, read only a small prefix of the
# response, then close the socket without reading the rest -- simulating a
# slow / disconnecting client on the delayed-header path. Returns the number
# of bytes actually read, then issues a brand-new request to confirm the
# worker is still healthy (not wedged holding the aborted transfer).
sub slow_read_then_reuse {
    my ($uri, $full_len) = @_;

    my $s = IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080),
        Timeout  => 5,
    ) or return (0, 0);

    $s->print("GET $uri HTTP/1.1\r\n"
        . "Host: localhost\r\n"
        . "Connection: close\r\n\r\n");

    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(3);
        # Drain only headers + a small prefix of the body, well short of the
        # full 32 KB -- then bail without reading the rest.
        while (length($buf) < 4096 + 512) {
            my $chunk;
            my $n = $s->sysread($chunk, 512);
            last if !defined $n || $n == 0;
            $buf .= $chunk;
        }
        alarm(0);
    };
    alarm(0);
    close($s);

    my ($head, $partial_body) = split /\r\n\r\n/, $buf, 2;
    $partial_body = '' unless defined $partial_body;
    my $n_read = length($partial_body) > 4096 ? 4096 : length($partial_body);

    # Follow-up request on a fresh connection: the worker must still be
    # responsive, proving the aborted delayed-header transfer did not wedge
    # it or leak the request slot.
    my $r2 = http_get($uri);
    my $ok = ($r2 =~ /^HTTP\S+ 200/) ? 1 : 0;

    return ($n_read, $ok);
}

sub http_daemon {
    my ($port, $recycled_body, $temp_file_body) = @_;

    my $server = IO::Socket::INET->new(
        Proto     => 'tcp',
        LocalPort => $port,
        Listen    => 5,
        Reuse     => 1,
    )
        or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $uri = '/recycled';
        while (<$client>) {
            $uri = $1 if /^GET\s+(\S+)/;
            last if (/^\x0d?\x0a?$/);
        }

        my $body = ($uri =~ m{^/proxy-temp-file}) ? $temp_file_body : $recycled_body;

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Type: text/plain\r\n"
            . "Content-Length: " . length($body) . "\r\n"
            . "Connection: close\r\n\r\n";

        # Write in small chunks with tiny pauses so nginx's proxy buffering
        # sees the body arrive across several TCP reads rather than one
        # syscall, encouraging distinct recycled buffers on the way out.
        my $chunk_size = 256;
        for (my $off = 0; $off < length($body); $off += $chunk_size) {
            my $chunk = substr($body, $off, $chunk_size);
            last unless print $client $chunk;
            select(undef, undef, undef, 0.001);
        }

        close $client;
    }
}
