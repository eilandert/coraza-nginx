#!/usr/bin/perl

# Tests for Coraza-nginx connector (delayed-response buffering cap).
#
# The header filter delays response headers until phase 4 completes so a
# phase-4 rule can still return a clean error page.  While delayed, the body
# filter accumulates every response buffer into the request pool.  For a large
# or open-ended (streaming) response that buffering would grow without limit
# and OOM the worker.
#
# The fix caps the accumulation at NGX_HTTP_CORAZA_MAX_DELAYED_BODY (1 MiB by
# default): once exceeded, the delayed headers + everything buffered so far are
# flushed and the remainder streams through.  This test drives a response well
# past the cap (with SecResponseBodyAccess Off, so the body is still delayed
# and buffered but Coraza itself does not inspect/limit it) and asserts:
#   1. the response still completes with 200 and an intact body, and
#   2. the connector logged that it flushed early (the cap path executed).
# See src/ngx_http_coraza_body_filter.c (NGX_HTTP_CORAZA_MAX_DELAYED_BODY).
#
# The /big case above only exercises the fail-open half of the cap: nothing
# in that body should ever match, so it cannot tell a real "still inspects
# up to the cap" connector apart from one that stopped inspecting on the
# first delayed buffer. Two more locations close that gap with
# SecResponseBodyAccess On:
#   * /before-cap places the matching marker in the first few bytes, well
#     under the cap -- deny must still fire and 403, proving buffered
#     content is genuinely inspected while delayed, not just passed through.
#   * /after-cap places the marker only past the 1 MiB cap. Once flushed,
#     content is streamed straight to the client and is no longer collected
#     for inspection, so the rule must NOT fire: the response completes
#     200 with the marker delivered to the client but never seen by
#     Coraza -- truncated inspection, not a silent full-body pass.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log %%TESTDIR%%/cap.log warn;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location /big {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess Off
            ';
        }

        location /before-cap {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@contains EARLY-MARKER" "id:451,phase:4,deny,log,status:403"
            ';
        }

        location /after-cap {
            default_type application/octet-stream;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@contains LATE-MARKER" "id:452,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

# 4 MiB response — comfortably past the 1 MiB default cap, delivered in many
# buffers so pending_bytes crosses the cap before last_buf arrives.
my $size = 4 * 1024 * 1024;
$t->write_file("/big", "Z" x $size);

# Marker in the first bytes: well inside the 1 MiB cap, so it must still be
# seen and blocked before any flush happens.
$t->write_file("/before-cap", "EARLY-MARKER" . ("Y" x $size));

# Marker placed only after the 1 MiB cap: by the time these bytes arrive the
# connector has already flushed and stopped collecting, so it must NOT be
# seen (must NOT block) even though the rule would clearly match it if
# inspection continued past the cap.
my $pad = 2 * 1024 * 1024;
$t->write_file("/after-cap", ("X" x $pad) . "LATE-MARKER");

$t->run();
$t->todo_alerts();
$t->plan(7);

###############################################################################

my $r = http_get('/big');
like($r, qr/^HTTP.*200/, 'oversized delayed response still returns 200');

my ($body) = $r =~ /\r\n\r\n(.*)$/s;
is(length($body // ''), $size, 'oversized response body delivered intact');

# A marker well before the cap must still be inspected and blocked: this is
# the deny-side control that /big's fail-open assertions above cannot
# provide, since nothing in /big's body can ever match.
my $r_early = http_get('/before-cap');
like($r_early, qr/^HTTP.*403/,
    'rule match before the buffering cap still blocks (deny is not bypassed by delayed buffering)');

# A marker placed only past the cap must NOT be seen: once the connector
# flushes and starts streaming, it stops collecting for inspection, so the
# response completes normally (200, marker delivered) rather than being
# silently fully inspected -- this is the truncation the cap exists to
# produce, made observable instead of assumed.
my $r_late = http_get('/after-cap');
like($r_late, qr/^HTTP.*200/,
    'rule match placed only after the buffering cap is not seen (inspection truncates, not a silent full pass)');
my ($late_body) = $r_late =~ /\r\n\r\n(.*)$/s;
like($late_body // '', qr/LATE-MARKER/,
    'the un-inspected marker still reaches the client, confirming the body was streamed through rather than dropped');

$t->stop();
like($t->read_file('cap.log'), qr/flushing headers early/,
    'connector flushed delayed headers once the buffering cap was exceeded');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
