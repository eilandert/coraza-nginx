#!/usr/bin/perl

# Tests for Coraza-nginx connector: the fail-closed branch in
# ngx_http_coraza_append_request_body_file() when the connector's own
# by-name ngx_open_file() of the client-body temp file fails
# (src/ngx_http_coraza_pre_access.c:121).
#
# The connector re-opens the temp file BY NAME with its own descriptor,
# separate from the ngx_http_request_t body handling that already wrote it
# (see the function's header comment). client_body_in_file_only forces the
# temp-file path deterministically; making the temp directory unreadable
# after nginx has started (so the request-body write that created the file
# already succeeded) makes the connector's own re-open fail without any
# fault-injection hook or src/ change.
#
# Only branch 2 of the three fail-closed branches in that function is
# covered here:
#   - body_size < 0 (:108) and the short-read n == 0 branch (:152) have no
#     externally reachable trigger without modifying src/ or adding a
#     fault-injection shim: body_size is nginx's own ngx_temp_file_t
#     offset (never negative in practice) and a short read on a file the
#     connector itself just successfully opened and sized via body_size
#     would require racing/truncating the temp file out from under a
#     concurrent nginx process, which is not a deterministic, reproducible
#     test setup. Faking either would not detect a real regression, so they
#     are intentionally omitted rather than stubbed.

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

my $t = Test::Nginx->new()->has(qw/http proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log %%TESTDIR%%/open_fail.log warn;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location /body {
            # Force the request body onto disk so the temp-file inspection
            # path (the connector's chunked temp-file reader) is exercised.
            client_body_in_file_only on;
            client_body_temp_path %%TESTDIR%%/body_temp;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

mkdir($t->testdir() . '/body_temp')
	or die "cannot create body_temp dir: $!";

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(4);

###############################################################################

# Positive/negative control: with the temp dir still readable, a
# file-backed body passes through cleanly and no open-failure log line
# appears.
like(http_req_body('POST', '/body', 'x=harmless value'),
    qr/TEST-OK-IF-YOU-SEE-THIS/,
    'clean path: file-backed request body reaches the upstream');

my $clean_log = $t->read_file('open_fail.log');
unlike($clean_log, qr/open\(\) ".*failed/,
    'clean path: no temp-file open-failure log line');

# nginx's own request-body write happens before the connector's read-side
# re-open, so revoking read+execute on the temp dir after startup leaves
# the write path unaffected but breaks the connector's by-name reopen.
chmod 0000, $t->testdir() . '/body_temp';

like(http_req_body('POST', '/body', 'x=another value'),
    qr/^HTTP\S+ 500/,
    'unreadable temp dir: request fails closed with 500');

$t->stop();

# Restore permissions so Test::Nginx can clean up the test directory.
chmod 0755, $t->testdir() . '/body_temp';

like($t->read_file('open_fail.log'),
    qr/open\(\) ".*body_temp.*failed/,
    'unreadable temp dir: connector logs the by-name open failure');

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		# Drain the forwarded request body so nginx's upstream write
		# completes; responding before reading it leaves bytes in the
		# socket and makes the proxy round-trip race (intermittent 502).
		if ($headers =~ /Content-Length:\s*(\d+)/i) {
			my $need = $1;
			my $got = 0;
			while ($got < $need) {
				my $buf;
				my $n = read($client, $buf, $need - $got);
				last if !defined $n || $n == 0;
				$got += $n;
			}
		}

		print $client "HTTP/1.1 200 OK" . CRLF;
		print $client "Content-Length: 23" . CRLF;
		print $client "Connection: close" . CRLF . CRLF;
		print $client "TEST-OK-IF-YOU-SEE-THIS";

		close $client;
	}
}

sub http_req_body {
	my ($method, $uri, $body) = @_;
	return http(
		"$method $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Type: application/x-www-form-urlencoded" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

###############################################################################
