#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed response headers vs Range).
#
# coraza_delay_response_headers returns NGX_OK from the Coraza header filter
# instead of calling the next header filter, so every header filter below this
# module -- including ngx_http_range_header_filter -- is skipped at
# ngx_http_send_header() time and only runs later, from the body filter.
#
# ngx_http_range_body_filter sits ABOVE the Coraza body filter, so the body
# passes it before the range HEADER filter has created its context.  The body
# is therefore never sliced, and the range header filter then stamps 206 +
# Content-Range + a short Content-Length onto a full-length body: the framing
# on the wire no longer matches the declared Content-Length, which is a
# response-smuggling primitive and, on a large file, a large amplification.
#
# These tests assert the wire truth: the number of body bytes actually sent
# must equal the declared Content-Length, for both a single range and a
# multipart/byteranges response.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Socket::INET;

use constant CRLF => "\x0d\x0a";

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # Delay is ON here (the shipped default): this is the path under test.
        location /delayed {
            default_type text/plain;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
            ';
        }

        # Negative control: identical location with the delay switched OFF.
        # Range handling must be correct here both before and after the fix,
        # so a failure in this location means the rig is broken, not the bug.
        location /nodelay {
            default_type text/plain;
            coraza on;
            coraza_delay_response_headers off;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
            ';
        }
    }
}
EOF

# 61 bytes exactly.
my $BODY = 'RANGE-DESYNC-CANARY-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-END';
die "fixture must be 61 bytes, got " . length($BODY) if length($BODY) != 61;

$t->write_file('/delayed', $BODY);
$t->write_file('/nodelay', $BODY);

$t->run();
$t->todo_alerts();

###############################################################################

# --- single range, delay ON (the bug) ---------------------------------------

my $r = raw_request("GET /delayed HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-9" . CRLF
	. "Connection: close" . CRLF . CRLF);

# A server may always ignore Range and return the whole entity (RFC 9110
# section 14.2), which is what the fixed delayed path does: it clears
# r->allow_ranges rather than emitting a 206 whose body was never sliced.
# What must never happen is a 206 that disagrees with its own body, so assert
# a coherent status here and the framing below.
like($r, qr!^HTTP/1\.1 20(0|6)!, 'single range: 200 OK or 206 Partial Content');

my ($content_length, $body) = split_response($r);
cmp_ok(defined $content_length ? $content_length : -1, '>', 0,
	'single range: response declares a Content-Length');
is(length($body), $content_length,
	'single range: body bytes on the wire equal Content-Length');

# --- multipart range, delay ON (the bug) ------------------------------------

$r = raw_request("GET /delayed HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-4,10-14" . CRLF
	. "Connection: close" . CRLF . CRLF);

like($r, qr!^HTTP/1\.1 20(0|6)!,
	'multipart range: 200 OK or 206 Partial Content');

($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'multipart range: body bytes on the wire equal Content-Length');

# A multipart/byteranges response from the delayed path is the specific shape
# that cannot be produced coherently here: the body already passed the range
# body filter unsliced, so if this header ever comes back the parts were never
# framed.  Pin it -- this is the assertion that fails if the allow_ranges reset
# is removed but the Content-Length happens to line up.
unlike($r, qr!multipart/byteranges!i,
	'multipart range: delayed path does not emit multipart/byteranges');

# --- negative control: same requests with the delay OFF ---------------------

$r = raw_request("GET /nodelay HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-9" . CRLF
	. "Connection: close" . CRLF . CRLF);

($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'negative control (delay off), single range: body equals Content-Length');

$r = raw_request("GET /nodelay HTTP/1.1" . CRLF
	. "Host: localhost" . CRLF
	. "Range: bytes=0-4,10-14" . CRLF
	. "Connection: close" . CRLF . CRLF);

($content_length, $body) = split_response($r);
is(length($body), $content_length,
	'negative control (delay off), multipart range: body equals Content-Length');

###############################################################################

# Split a raw response into its declared Content-Length and the bytes that
# actually followed the header terminator.  Returns (undef, '') when there is
# no Content-Length, so the caller's cmp_ok above fails loudly rather than
# comparing against an accidental 0.
sub split_response {
	my ($raw) = @_;

	my $sep = index($raw, CRLF . CRLF);
	return (undef, '') if $sep < 0;

	my $head = substr($raw, 0, $sep);
	my $body = substr($raw, $sep + 4);

	my ($len) = $head =~ /^Content-Length:\s*(\d+)\s*$/mi;
	return ($len, $body);
}

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
		alarm(10);
		local $/;
		$reply = <$s> // '';
		alarm(0);
	};
	# Rethrow a timeout instead of returning '': a silent '' would make the
	# length comparisons above pass vacuously (0 == 0) on a hung connection.
	if (my $err = $@) {
		alarm(0);
		close $s;
		die $err;
	}
	close $s;
	return $reply;
}

###############################################################################
