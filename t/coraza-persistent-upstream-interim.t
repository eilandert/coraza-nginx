#!/usr/bin/perl

# Tests for Coraza-nginx connector (persistent upstream, interim/no-body
# statuses, misleading framing).
#
# With `keepalive` on the upstream block nginx reuses ONE TCP connection to
# the origin across requests. Three status classes never carry a body the
# connector's phase-4 body filter can wait on:
#
#   * 103 Early Hints followed by the real final response on the SAME
#     connection -- the connector must not treat the 103 as the final
#     header set and must not stall waiting for a body that belongs to the
#     103, and the persistent connection must still be reusable for the
#     request that follows.
#   * 204 No Content -- must never carry a body per RFC 9110 regardless of
#     what Content-Length/Transfer-Encoding the origin (misleadingly) sends.
#   * 304 Not Modified -- same body-less contract, tested with the same
#     misleading framing.
#
# Each is sent with misleading Content-Length / Transfer-Encoding / surplus
# body bytes past what the status legitimately allows, on a connection that
# is then reused for a plain request. The oracle: no delayed-header stall
# (bounded read completes within the alarm), and the response that follows
# on the same connection is the correct, uncontaminated one -- proving the
# extra bytes were not left on the wire to be misread as the start of the
# next response.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use constant CRLF => "\x0d\x0a";

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream backend {
        server 127.0.0.1:%%PORT_8081%%;
        keepalive 4;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@contains BADBODY" "id:7400,phase:4,t:none,deny,log,status:403"
            ';
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
EOF

# Captured as a plain string before the daemon forks: a named sub closing
# over $t (rather than a plain string) keeps $t's refcount alive until
# global destruction, which shifts Test::Nginx's DESTROY-time "no
# alerts"/"no sanitizer errors" checks past Test::Builder's own end-of-run
# plan verification and produces a spurious "planned N tests but ran N-2"
# diagnostic with a nonzero exit despite every subtest passing.
my $testdir = $t->testdir();

$t->run_daemon(\&origin_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# One client connection to nginx, kept open across all three cases plus a
# trailing control request -- proves neither a stalled header delay nor
# leftover bytes from a body-less status corrupt the NEXT response read off
# the same connection.

my $s = IO::Socket::INET->new(
	Proto => 'tcp',
	PeerAddr => '127.0.0.1:' . port(8080),
) or die "Can't connect to nginx: $!\n";
$s->autoflush(1);

# --- case 1: 103 Early Hints then the final response ----------------------

my $r103 = client_request($s, '/early-hints');
unlike($r103, qr/^$/, '103-then-final: response received without a delayed-header stall');
like($r103, qr!^HTTP/1\.1 200!,
	'103-then-final: client sees the FINAL status, not the interim 103');
unlike($r103, qr!103!, '103-then-final: the 103 status line itself is not surfaced to the client');

# --- case 2: 204 No Content with misleading framing ------------------------

my $r204 = client_request($s, '/no-content');
like($r204, qr!^HTTP/1\.1 204!, '204: status line passed through');
unlike($r204, qr!BADBODY!,
	'204: no body delivered to the client despite the origin sending one');

# --- case 3: 304 Not Modified with misleading framing -----------------------

my $r304 = client_request($s, '/not-modified');
like($r304, qr!^HTTP/1\.1 304!, '304: status line passed through');
unlike($r304, qr!BADBODY!,
	'304: no body delivered to the client despite the origin sending one');

# --- control: the connection is still usable for a plain request afterward -

my $rctrl = client_request($s, '/plain');
like($rctrl, qr!^HTTP/1\.1 200!,
	'control: connection still serves a correct response after three '
	. 'body-less/interim statuses (no contamination, no stall)');
like($rctrl, qr!PLAIN-OK!,
	'control: the plain response body is exactly the next response, not '
	. 'leftover bytes from an earlier case');

close $s;

$t->stop();

is(origin_saw('unexpected'), 0,
	'origin never received a request URI other than the four sent '
	. '(rules out request-side desync from the misleading responses)');

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling interim/no-body statuses on a persistent upstream');

###############################################################################

sub client_request {
	my ($sock, $uri) = @_;

	print $sock "GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF . CRLF;

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(5);
		# Read until we have a full status-line + headers block; for the
		# body-less cases that IS the whole response, for /plain and the
		# early-hints case we also drain the Content-Length body so the
		# next read on the connection starts at the next response.
		while (1) {
			my $buf;
			my $n = sysread($sock, $buf, 4096);
			last unless $n;
			$reply .= $buf;
			last if response_complete($reply);
		}
		alarm(0);
	};
	return $reply;
}

# Heuristic completion check good enough for this fixture's small, known
# response shapes: headers terminated, and if a Content-Length is present
# the body has fully arrived.
sub response_complete {
	my ($buf) = @_;

	return 0 unless $buf =~ /\r\n\r\n/;

	my ($head, $rest) = split /\r\n\r\n/, $buf, 2;
	$rest //= '';

	if ($head =~ /^HTTP\/1\.1 (204|304)/) {
		return 1;
	}

	if ($head =~ /Content-Length:\s*(\d+)/i) {
		return length($rest) >= $1;
	}

	# No Content-Length and not body-less: treat headers-complete as done
	# for this fixture (used only by the 103 case, whose final response
	# below always sets Content-Length).
	return 1;
}

sub origin_saw {
	my ($tag) = @_;
	my $file = $testdir . "/seen-$tag";
	return -f $file ? 1 : 0;
}

# --- origin daemon: ONE persistent connection, four sequential requests ---

sub origin_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	# Accept connections in a loop, not once: Test::Nginx's own
	# waitforsocket() readiness probe opens and immediately closes a
	# connection before the real client ever connects, and nginx itself may
	# open a fresh upstream connection if it does not keep the first one
	# alive. A single accept() would consume the probe's connection and
	# leave the real traffic unserved. Each accepted connection is served
	# until the peer stops sending requests (EOF), then we accept the next.
	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (1) {
			my $headers = '';
			while (<$client>) {
				$headers .= $_;
				last if (/^\x0d?\x0a?$/);
			}

			last unless length($headers);

			my ($uri) = $headers =~ /^\S+\s+(\S+)/;
			$uri //= '';

			if ($uri eq '/early-hints') {
				# Interim 103 first, no body, then the real final response
				# -- both on the same connection, back to back.
				print $client "HTTP/1.1 103 Early Hints\r\n"
					. "Link: </style.css>; rel=preload\r\n\r\n";
				print $client "HTTP/1.1 200 OK\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "EH-DONE";
			} elsif ($uri eq '/no-content') {
				# 204 must never carry a body; send misleading framing
				# headers plus a body anyway to prove nginx/coraza strip it
				# regardless.
				print $client "HTTP/1.1 204 No Content\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "BADBODY";
			} elsif ($uri eq '/not-modified') {
				print $client "HTTP/1.1 304 Not Modified\r\n"
					. "Content-Length: 7\r\n\r\n"
					. "BADBODY";
			} elsif ($uri eq '/plain') {
				my $body = "PLAIN-OK\n";
				print $client "HTTP/1.1 200 OK\r\n"
					. "Content-Length: " . length($body) . "\r\n\r\n"
					. $body;
			} else {
				open(my $fh, '>', $testdir . "/seen-unexpected");
				close($fh);
				print $client "HTTP/1.1 500 Internal Server Error\r\n"
					. "Content-Length: 0\r\n\r\n";
			}
		}

		close $client;
	}
}

###############################################################################
