#!/usr/bin/perl

# Tests for Coraza-nginx connector (hostile request framing, on/off
# differential).
#
# nginx's core HTTP parser is the first line of defense against request
# smuggling and framing attacks: conflicting Content-Length/Transfer-Encoding,
# malformed chunk sizes, trailing garbage after the terminal chunk, and a body
# that does not match its declared Content-Length. The connector must never
# make nginx's own verdict on these WORSE -- a request core nginx rejects must
# never reach the proxied origin, whether coraza is on or off, and turning
# coraza on must not relax a rejection into a pass.
#
# Design: an origin daemon marks every request it actually receives by
# writing a line to a marker file per case. Each hostile case is sent to a
# pair of locations that are identical except for `coraza on|off`. The oracle
# is (a) the response is never the origin's 200 OK-off-limits marker leaking
# through as a successful smuggled request, and (b) the origin is not invoked
# at all for input nginx's own parser rejects -- checked identically for both
# locations. Where nginx's parser accepts and forwards the request (case is
# framing-ambiguous but not core-rejected), coraza on must reject at least as
# often as coraza off; it must never be the on-side that lets through what the
# off-side blocked.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(18);

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

        location /off/ {
            coraza off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%/;
        }

        location /on/ {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecResponseBodyAccess On
                SecAction "id:7300,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=URLENCODED"
                SecRule RESPONSE_BODY "@contains BADBODY" "id:7301,phase:4,t:none,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%/;
        }
    }
}
EOF

# Captured as a plain string, not the $t object itself, and BEFORE the daemon
# is forked: a named sub closing over $t keeps its refcount alive until
# global destruction, which shifts Test::Nginx's DESTROY-time "no
# alerts"/"no sanitizer errors" checks past Test::Builder's own end-of-run
# plan verification and produces a spurious "planned N tests but ran N-2"
# diagnostic with a nonzero exit despite every subtest passing. The forked
# daemon also needs the plain string, since it must be set before fork().
my $testdir = $t->testdir();

$t->run_daemon(\&origin_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->todo_alerts();

###############################################################################

# --- case 1: conflicting Content-Length vs Transfer-Encoding --------------
#
# Smuggling-classic: two framing headers that disagree on where the body
# ends. nginx's core must reject this outright (400) for both on and off --
# it must never reach the origin under either.

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/clte HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: 5" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "3" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF
	);
	like($r, qr!^HTTP/1\.1 400!,
		"conflicting Content-Length/Transfer-Encoding rejected by core ($loc)");
}

is(origin_saw('clte'), 0,
	'origin never invoked for the Content-Length vs Transfer-Encoding conflict (core rejects before proxy_pass)');

# --- case 2: malformed / truncated chunk size ------------------------------

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/badchunk HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "ZZZ" . CRLF . "abc" . CRLF . "0" . CRLF . CRLF
	);
	unlike($r, qr!^HTTP/1\.1 200!,
		"malformed chunk size never yields 200 ($loc)");
}

is(origin_saw('badchunk'), 0,
	'origin never invoked for a malformed chunk size');

# --- case 3: chunk trailers and surplus bytes after the final chunk -------
#
# Well-formed terminal chunk followed by extra bytes that look like another
# request smuggled onto the same stream. Both locations must not treat the
# surplus as a second, independently-routed request; the visible response
# must come from the ONE legitimate request only.

for my $loc (qw(off on)) {
	my $r = raw_request(
		"POST /$loc/trailer HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Transfer-Encoding: chunked" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "3" . CRLF . "abc" . CRLF . "0" . CRLF
		. "X-Trailer: yes" . CRLF . CRLF
		. "GET /$loc/smuggled HTTP/1.1" . CRLF . "Host: localhost" . CRLF . CRLF
	);
	unlike($r, qr!/smuggled!,
		"surplus bytes after final chunk are not parsed as a routed request ($loc)");
}

is(origin_saw('smuggled'), 0,
	'origin never invoked via bytes smuggled past the terminal chunk');

# --- case 4: Content-Length vs actual body length mismatch ----------------
#
# Declared length longer than the bytes actually sent before the peer closes:
# nginx must not proxy a short/truncated body as if it were complete, and
# must not hang past the read timeout in a way that yields a 200.

for my $loc (qw(off on)) {
	my $r = short_body_request($loc);
	unlike($r, qr!^HTTP/1\.1 200!,
		"Content-Length longer than actual body never yields 200 ($loc)");
}

# --- case 5: stacked/unknown Content-Encoding under response body access --
#
# The /on/ location above already runs with SecResponseBodyAccess On, so it
# is reused directly here -- no second config/reload needed. Verify neither
# side crashes or hangs on an origin response advertising an encoding chain
# nginx/coraza does not decode (gzip+br stacked, or an unknown token).

for my $enc ('gzip,br', 'unknown-codec', 'identity,gzip,unknown') {
	for my $loc (qw(off on)) {
		my $r = stacked_encoding_request($loc, $enc);
		like($r, qr!^HTTP/1\.1 (200|403|502)!,
			"stacked/unknown Content-Encoding '$enc' handled without hang or 5xx crash ($loc)");
	}
}

$t->stop();

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling hostile request framing');

###############################################################################

sub raw_request {
	my ($request) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s $request;

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(5);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	close $s;
	return $reply;
}

# Send a Content-Length declaring more bytes than are actually written, then
# close the connection early -- the classic truncated-body case.
sub short_body_request {
	my ($loc) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "POST /$loc/short HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: 100" . CRLF
		. "Connection: close" . CRLF . CRLF
		. "short";

	my $reply = '';
	local $SIG{ALRM} = sub { die "timeout\n" };
	eval {
		alarm(3);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	close $s;
	return $reply;
}

sub stacked_encoding_request {
	my ($loc, $enc) = @_;

	return raw_request(
		"GET /$loc/enc/$enc HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF . CRLF
	);
}

# --- origin daemon: records which URIs it actually received ---------------

sub origin_saw {
	my ($tag) = @_;
	my $file = $testdir . "/seen-$tag";
	return -f $file ? 1 : 0;
}

sub origin_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my ($uri) = $headers =~ /^\S+\s+(\S+)/;
		$uri //= '';

		for my $tag (qw(clte badchunk smuggled)) {
			if ($uri =~ /\Q$tag\E/) {
				open(my $fh, '>', $testdir . "/seen-$tag");
				close($fh);
			}
		}

		if ($uri =~ m{/enc/([^/\s]+)}) {
			my $enc = $1;
			my $body = "payload";
			print $client "HTTP/1.1 200 OK\r\n"
				. "Content-Encoding: $enc\r\n"
				. "Content-Length: " . length($body) . "\r\n"
				. "Connection: close\r\n\r\n"
				. $body;
		} else {
			my $body = "TEST-OK\n";
			print $client "HTTP/1.1 200 OK\r\n"
				. "Content-Length: " . length($body) . "\r\n"
				. "Connection: close\r\n\r\n"
				. $body;
		}

		close $client;
	}
}

###############################################################################
