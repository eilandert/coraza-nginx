#!/usr/bin/perl

# Tests for Coraza-nginx connector: every disruptive intervention blocks,
# regardless of the status the rule happens to carry.
#
# ngx_http_coraza_process_intervention() used to decide "was this request
# blocked?" from intervention->status (`if (intervention->status != 200)`) and
# return that status raw, while every caller tests `if (ret > 0)`. That is not
# a block decision, and two disruptive SecLang actions fell straight through it
# to the origin:
#
#   * a bare `drop` yields status 0. 0 is NGX_OK, so `ret > 0` was false, the
#     rewrite handler returned NGX_DECLINED and nginx proxied the request
#     upstream. Worse, status 0 still satisfied `!= 200`, so on the way out the
#     connector called coraza_update_status_code(tx, 0), logged
#     "Access denied with code 0" and ran the logging phase -- the operator's
#     audit trail claimed a block for a request that was actually served.
#     CRS uses bare `drop` for several paranoia-level and anomaly actions, so
#     any ruleset relying on those was not enforcing them.
#
#   * `deny,status:200` yields status 200, which `!= 200` excluded outright, so
#     the request was served with no audit record at all.
#
# intervention->disruptive is not a usable signal either: libcoraza 1.7.0
# leaves it 0 even for a plain `deny,status:403`.
#
# The fix derives blocked-ness from the intervention's existence -- libcoraza
# only allocates one for a disruptive action, and `allow`, `pass` and every
# rule under SecRuleEngine DetectionOnly yield NULL -- and maps the status the
# way Coraza's own reference middleware does (coraza/v3 http/middleware.go,
# obtainStatusCodeFromInterruptionOrDefault): honour ->status for `deny`, and
# for `drop` close the connection (NGX_HTTP_CLOSE).
#
# Each location below proxies to a real origin server whose access log is the
# oracle for "did this request reach the origin?". Asserting the client-visible
# status alone is not enough: a 403 error page and a genuinely-blocked request
# look the same from the client if the origin was hit anyway, and for `drop`
# the client sees a closed connection either way only if nothing was forwarded.
#
# See src/ngx_http_coraza_module.c (ngx_http_coraza_process_intervention).

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(29);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format origin_hit '$uri';

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        # The connector's "Access denied with code N" line is emitted only
        # when a transaction id is configured. It is the audit record under
        # test below: before the fix a bare `drop` logged "code 0" for a
        # request that was then served by the origin.
        coraza_transaction_id "tid-$request_id";

        # Bare `drop`: no status at all. Must close the connection and must
        # never reach the origin.
        location /drop {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8100,phase:1,drop,log,msg:\'drop-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # `deny` with an explicitly non-disruptive-looking status. Still a
        # disruptive action, so it must block and must not reach the origin.
        location /deny200 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8101,phase:1,deny,status:200,log,msg:\'deny200-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Ordinary deny. Pins that the fix did not change normal 403 handling.
        location /deny403 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8102,phase:1,deny,status:403,log,msg:\'deny403-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # Negative control: identical drop rule, but the request below does
        # not match it. Its own location (and therefore its own URI in the
        # origin access log) keeps the "/drop never reached the origin" oracle
        # unambiguous.
        location /control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:8104,phase:1,drop,log,msg:\'control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # DetectionOnly with the same drop rule: must still be allowed through
        # to the origin. This is the regression guard against turning
        # detection into blocking.
        location /detect {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:x "@streq bad" "id:8103,phase:1,drop,log,msg:\'detect-drop-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
        # --- phase:3 (RESPONSE_HEADERS) bare `drop` -------------------------
        #
        # This is a HEADER-FILTER site, not a rule-phase handler, and it is a
        # different code path from /drop above.  A phase handler returns
        # NGX_HTTP_CLOSE into ngx_http_finalize_request(), which special-cases
        # it and terminates.  The header filter instead finalizes through
        # ngx_http_filter_finalize_request() -> ngx_http_special_response_handler(),
        # where NGX_HTTP_CLOSE is not special at all: 444 matches none of the
        # error-page ranges (NGX_HTTP_NGINX_CODES is 494) and nginx emits a
        # well-formed zero-body `HTTP/1.1 444 ` response on a KEPT-ALIVE
        # connection -- the opposite of `drop`.  The assertions below are
        # written against that failure mode specifically.
        location /drop-p3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8110,phase:3,drop,log,msg:\'drop-p3-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # phase:3 negative control: same rule, origin sends a non-matching
        # header, so the response must come back intact.
        location /drop-p3-control {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8111,phase:3,drop,log,msg:\'drop-p3-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- phase:4 (RESPONSE_BODY) bare `drop` ----------------------------
        #
        # A BODY-FILTER site, reached through
        # ngx_http_coraza_body_filter_finalize().  Same NGX_HTTP_CLOSE problem
        # as phase:3.  Headers are delayed here so the drop is taken on the
        # delayed-headers branch -- the branch that would otherwise have a
        # clean error page available and is therefore most likely to emit a
        # tidy 444 instead of dropping.
        location /drop-p4 {
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx DROPME" "id:8112,phase:4,drop,log,msg:\'drop-p4-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # phase:4 negative control: same rule, body does not match.
        location /drop-p4-control {
            coraza on;
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx DROPME" "id:8113,phase:4,drop,log,msg:\'drop-p4-control-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        # --- deny,status:444 must NOT be treated as a drop ------------------
        #
        # 444 is a status an operator can legitimately ask for with `deny`,
        # and it is also the value NGX_HTTP_CLOSE happens to have.  Pins that
        # the connector keys the connection teardown on the ACTION being
        # `drop`, not on the resulting number, so this still produces an
        # ordinary response rather than a reset.
        location /deny444-p3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Probe "@streq bad" "id:8114,phase:3,deny,status:444,log,msg:\'deny444-probe\',t:none"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }

    # The origin. Its access log is the oracle for "was the request forwarded".
    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  origin;

        access_log %%TESTDIR%%/origin.log origin_hit;

        location / {
            return 200 "ORIGIN-REACHED";
        }

        # Origin arm for the phase:3 cases: emits the response header the
        # RESPONSE_HEADERS rule keys on. The value is taken from the query
        # argument so the matching and control requests differ only in that
        # one byte string and share every other code path.
        location /drop-p3 {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }
        location /drop-p3-control {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }
        location /deny444-p3 {
            add_header X-Probe $arg_p always;
            return 200 "ORIGIN-REACHED";
        }

        # Origin arm for the phase:4 cases: the body carries the token the
        # RESPONSE_BODY rule keys on. text/plain so it passes
        # SecResponseBodyMimeType and is actually inspected.
        location /drop-p4 {
            default_type text/plain;
            return 200 "ORIGIN-REACHED-DROPME-PAYLOAD";
        }
        location /drop-p4-control {
            default_type text/plain;
            return 200 "ORIGIN-REACHED-BENIGN-PAYLOAD";
        }
    }
}

EOF

$t->run();

###############################################################################

# Raw-socket GET. Returns the bytes nginx sent back, which is the empty string
# when the connection was closed without a response -- the observable that
# distinguishes a `drop` from anything that produces a status line.
sub raw_get {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	print $s "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n";

	local $/ = undef;
	my $resp = <$s>;
	close $s;

	return defined $resp ? $resp : '';
}

# Two PIPELINED keep-alive requests on ONE socket, returning both replies.
#
# This is the oracle that separates a real `drop` from nginx serving a tidy
# zero-body 444: ngx_http_special_response_handler() leaves the connection
# reusable, so the broken path answers the second request too. A dropped
# connection cannot answer it, so the second reply is empty.
#
# Both requests are written before reading anything, so the second is already
# in the socket buffer when nginx decides what to do with the first -- nginx
# cannot "not have received it yet", and an empty second reply means the
# connection really was torn down rather than merely slow.
sub raw_get_keepalive_pair {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";
	$s->autoflush(1);

	# Request 1 keeps the connection open; request 2 is the reuse probe and
	# targets a location that is always benign, so anything coming back for
	# it is proof the socket survived request 1.
	print $s "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n\r\n"
		. "GET /control?x=fine HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Connection: close\r\n\r\n";

	local $/ = undef;
	my $resp = <$s>;
	close $s;

	$resp = '' unless defined $resp;

	# Split on the second status line, if there is one.
	my @parts = split /(?=HTTP\/1\.[01] )/, $resp;
	my $first  = defined $parts[0] ? $parts[0] : '';
	my $second = defined $parts[1] ? join('', @parts[1 .. $#parts]) : '';

	return ($first, $second);
}

# --- bare `drop` -------------------------------------------------------------

my $drop = raw_get('/drop?x=bad');

# Expected: nothing at all on the wire (NGX_HTTP_CLOSE terminates the
# connection without writing a response).
# Observed before the fix: "HTTP/1.1 200 OK ... ORIGIN-REACHED" -- the request
# was proxied and the origin's response came back.
unlike($drop, qr!ORIGIN-REACHED!,
	'bare drop does not return the origin response');
unlike($drop, qr!^HTTP/\S+ 200!,
	'bare drop does not return 200');
is($drop, '',
	'bare drop closes the connection without sending a response');

# --- deny,status:200 ---------------------------------------------------------

my $deny200 = raw_get('/deny200?x=bad');

# Expected: blocked -- the origin's body must not come back. Returning 200 from
# a phase handler makes ngx_http_finalize_request() finalize the connection
# without ever running the content phase, so the client gets an empty 200.
# Observed before the fix: "ORIGIN-REACHED".
unlike($deny200, qr!ORIGIN-REACHED!,
	'deny,status:200 does not return the origin response');

# --- ordinary deny (must not regress) ----------------------------------------

my $deny403 = raw_get('/deny403?x=bad');
like($deny403, qr!^HTTP/\S+ 403!,
	'deny,status:403 still returns 403');
unlike($deny403, qr!ORIGIN-REACHED!,
	'deny,status:403 does not return the origin response');

# --- DetectionOnly (must not regress into blocking) --------------------------

my $detect = raw_get('/detect?x=bad');
like($detect, qr!^HTTP/\S+ 200!,
	'DetectionOnly does not block a matching drop rule');
like($detect, qr!ORIGIN-REACHED!,
	'DetectionOnly forwards the matching request to the origin');

# --- negative control --------------------------------------------------------
#
# A benign request to the same drop location, differing only in the argument
# value so the rule does not match. This proves the three assertions above are
# the rule firing and not the location being broken, unreachable, or
# misconfigured in a way that would close every connection.

my $benign = raw_get('/control?x=fine');
like($benign, qr!^HTTP/\S+ 200!,
	'negative control: non-matching request to the drop location returns 200');
like($benign, qr!ORIGIN-REACHED!,
	'negative control: non-matching request to the drop location reaches the origin');


# --- phase:3 / phase:4 bare `drop` -------------------------------------------
#
# These are the two FILTER sites. They do not share the rewrite handler's
# teardown: a phase handler hands NGX_HTTP_CLOSE to
# ngx_http_finalize_request(), which special-cases it
# (`if (rc == NGX_HTTP_CLOSE) { c->timedout = 1; ngx_http_terminate_request(); }`)
# and really drops the connection. A filter finalizes through
# ngx_http_filter_finalize_request() -> ngx_http_special_response_handler(),
# which has no NGX_HTTP_CLOSE case at all, so 444 is handled as an ordinary
# error status, matches none of the error-page ranges (NGX_HTTP_NGINX_CODES is
# 494) and falls through to `err = 0`. nginx then writes a well-formed
# zero-body response whose status line is the literal "HTTP/1.1 444 " (444 is
# absent from ngx_http_status_lines[]) and KEEPS THE CONNECTION ALIVE.
#
# So the assertions are written against that exact failure mode: no status
# line of any kind, and the connection must not survive to serve a second
# request on the same socket.

my $drop_p3 = raw_get('/drop-p3?p=bad');

unlike($drop_p3, qr!ORIGIN-REACHED!,
	'phase:3 drop does not return the origin response body');
unlike($drop_p3, qr!^HTTP/!,
	'phase:3 drop writes no status line at all');
unlike($drop_p3, qr!\b444\b!,
	'phase:3 drop does not emit a 444 status line');
is($drop_p3, '',
	'phase:3 drop closes the connection without sending a response');

my $drop_p4 = raw_get('/drop-p4');

unlike($drop_p4, qr!ORIGIN-REACHED!,
	'phase:4 drop does not return the origin response body');
unlike($drop_p4, qr!^HTTP/!,
	'phase:4 drop writes no status line at all');
unlike($drop_p4, qr!\b444\b!,
	'phase:4 drop does not emit a 444 status line');
is($drop_p4, '',
	'phase:4 drop closes the connection without sending a response');

# --- keep-alive reuse oracle -------------------------------------------------
#
# The sharpest discriminator between "dropped" and "served a tidy 444".
# ngx_http_special_response_handler() leaves the connection reusable, so the
# broken behaviour answers a SECOND pipelined request on the same socket. A
# real drop cannot: the connection is gone after the first.

# Only the first reply is bound: the second is deliberately not examined,
# for the reason spelled out below.
my ($p3_first) = raw_get_keepalive_pair('/drop-p3?p=bad');

# Assert on the FIRST reply, not merely on the absence of a second.
#
# Asserting only that the second reply is empty would be vacuous here, and was
# observed to be so: the broken build answers request 1 with a 444 carrying
# `Connection: close`, so it does not serve request 2 either and an
# empty-second-reply assertion passes on BOTH the broken and the fixed build.
# What actually differs is whether anything was written at all, so that is
# what is asserted -- with the pipelined second request still present to prove
# the socket was readable and the emptiness is nginx's choice, not a race.
is($p3_first, '',
	'phase:3 drop writes nothing even with a second request already queued');

# Only the first reply is bound; see the phase:3 case above.
my ($p4_first) = raw_get_keepalive_pair('/drop-p4');
is($p4_first, '',
	'phase:4 drop writes nothing even with a second request already queued');

# --- phase:3 / phase:4 negative controls -------------------------------------
#
# Same locations, same rules, non-matching data. Proves the assertions above
# are the rule firing and not the location being broken in a way that would
# close every connection.

my $p3_ok = raw_get('/drop-p3-control?p=fine');
like($p3_ok, qr!ORIGIN-REACHED!,
	'negative control: non-matching phase:3 response is returned intact');

my $p4_ok = raw_get('/drop-p4-control');
like($p4_ok, qr!ORIGIN-REACHED-BENIGN-PAYLOAD!,
	'negative control: non-matching phase:4 response is returned intact');

# --- deny,status:444 is not a drop -------------------------------------------
#
# 444 is both a status an operator may legitimately request with `deny` and
# the numeric value of NGX_HTTP_CLOSE. The connector must key the connection
# teardown on the ACTION, so this one still produces an ordinary response.

my $deny444 = raw_get('/deny444-p3?p=bad');
like($deny444, qr!^HTTP/!,
	'deny,status:444 is answered with a response, not a dropped connection');
unlike($deny444, qr!ORIGIN-REACHED!,
	'deny,status:444 still blocks the origin body');

$t->stop();

###############################################################################

# The origin's own access log is the authoritative record of what was actually
# forwarded. Checking the client-visible response alone cannot distinguish
# "blocked" from "forwarded, and the origin's reply happened to look like a
# block".
my $origin_log = $t->read_file('origin.log');
$origin_log = '' unless defined $origin_log;

unlike($origin_log, qr!^/drop$!m,
	'no dropped request ever reached the origin');
unlike($origin_log, qr!^/deny200$!m,
	'no deny,status:200 request ever reached the origin');

# The audit trail must not claim a block with a status the client never got.
# Before the fix a bare `drop` produced exactly this line and then served the
# request from the origin anyway, so an operator reading the log saw a block
# that never happened.
my $errlog = $t->read_file('error.log');
$errlog = '' unless defined $errlog;

unlike($errlog, qr/Access denied with code 0\b/,
	'no request is logged as denied with the bogus status 0');

# The drop that really was blocked is recorded with the status the connector
# actually enforced (444, nginx's "connection closed without response").
like($errlog, qr/Access denied with code 444\b/,
	'a dropped request is logged as denied with the status it was blocked with');

coraza_crash_check::assert_no_crash($t,
	'no crash handling drop and deny,status:200 interventions');

###############################################################################
