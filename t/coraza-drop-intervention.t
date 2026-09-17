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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(15);

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
    }

    # The origin. Its access log is the oracle for "was the request forwarded".
    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  origin;

        access_log %%TESTDIR%%/origin.log origin_hit;

        location / {
            return 200 "ORIGIN-REACHED";
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
