#!/usr/bin/perl

# Tests for Coraza-nginx connector: a phase-4 RESPONSE_BODY intervention that
# fires WHILE the response headers are being delayed.
#
# With coraza_delay_response_headers on and SecResponseBodyAccess On, the body
# filter buffers the response and inspects it before the headers are sent.  When
# a RESPONSE_BODY rule matches, the intervention must be applied on the
# still-delayed headers path (ctx->headers_delayed branch in the body filter),
# turning the buffered 200 into the rule's status.  A control location without
# a matching body confirms the same delayed 200 is released untouched.
#
# The delayed branch must produce the SAME client-visible response as the
# non-delayed one: a real ngx_http_filter_finalize_request(), which runs
# ngx_http_clean_header() + ngx_http_special_response_handler() and emits the
# status page.  Returning a bare status code from a body filter is not a
# finalize -- nginx propagates it up through ngx_http_output_filter() with no
# header ever written, so the client gets a truncated response or a reset.
# Asserting the status line alone cannot tell those two apart, so every
# blocked case below also asserts the error page BODY and asserts that the
# buffered origin body was discarded rather than leaked.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;
        default_type text/plain;

        # A custom 403 page is the sharpest oracle available here: only
        # ngx_http_special_response_handler() -- reached exclusively via
        # ngx_http_filter_finalize_request() -- consults error_page.  If the
        # delayed branch returns a bare status instead of finalizing, no
        # header and no page are written and this sentinel never appears.
        # Unlike nginx's built-in error HTML it does not depend on the
        # nginx version's markup.
        error_page 403 /denied-403.html;
        location = /denied-403.html {
            coraza off;
            internal;
        }

        # Blocked: RESPONSE_BODY rule matches while headers are delayed.
        location /block.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:300,phase:4,deny,log,status:403"
            ';
        }

        # Reference: identical rule with the header delay OFF.  This is the
        # sibling path that has always called ngx_http_filter_finalize_request,
        # so its response is the ground truth the delayed path must match.
        location /nodelay.txt {
            coraza_delay_response_headers off;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:302,phase:4,deny,log,status:403"
            ';
        }

        # Control: identical config, but the body does not contain the trigger,
        # so the delayed 200 is released intact.
        location /pass.txt {
            coraza_delay_response_headers on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 65536
                SecRule RESPONSE_BODY "@rx BLOCK ME" "id:301,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOF

my $clean = "harmless body, nothing matches\n";
my $origin = "leading text ... BLOCK ME ... trailing text\n";
my $denied = "DENIED-BY-PHASE4-ERROR-PAGE\n";
$t->write_file("/denied-403.html", $denied);
$t->write_file("/block.txt", $origin);
$t->write_file("/nodelay.txt", $origin);
$t->write_file("/pass.txt", $clean);

$t->run();
$t->todo_alerts();
$t->plan(9);

###############################################################################

my $blocked = http_get('/block.txt');

like($blocked, qr/^HTTP.*403/,
    'RESPONSE_BODY match while headers delayed -> blocked with rule status');

# The finalize path emits real response headers.  A bare status return from the
# body filter writes none at all, so the absence of a Content-Length here is
# the marker that separates the two -- status alone cannot.
like($blocked, qr/Content-Length: \d+/i,
    'delayed block emits real response headers, not a bare status');

# The sentinel only reaches the client through
# ngx_http_special_response_handler(), i.e. only if the delayed branch really
# finalized.  This is the assertion that fails if it returns a bare status.
like($blocked, qr/\Q$denied\E/,
    'delayed block emits the 403 error page body');

# The buffered origin body must be discarded, never leaked past the block.
unlike($blocked, qr/\QBLOCK ME\E/,
    'buffered origin body is not leaked on a delayed block');

# Ground truth: the non-delayed sibling, whose finalize was never in question.
my $nodelay = http_get('/nodelay.txt');
like($nodelay, qr/^HTTP.*403/,
    'RESPONSE_BODY match without header delay -> blocked with rule status');
like($nodelay, qr/\Q$denied\E/,
    'non-delayed block emits the 403 error page body');
unlike($nodelay, qr/\QBLOCK ME\E/,
    'buffered origin body is not leaked on a non-delayed block');

my $r = http_get('/pass.txt');
like($r, qr/^HTTP.*200/, 'non-matching delayed body -> released as 200');
like($r, qr/\Q$clean\E/, 'non-matching delayed body delivered intact');
