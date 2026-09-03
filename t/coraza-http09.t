#!/usr/bin/perl

# Tests for Coraza-nginx connector (HTTP/0.9 request version handling).
#
# A genuine HTTP/0.9 request (request line with no HTTP-version token) sets
# r->http_version == NGX_HTTP_VERSION_9, driving the case in
# src/ngx_http_coraza_rewrite.c that maps the version to "0.9" before handing
# it to coraza_process_uri().

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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location / {
            default_type text/plain;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@contains attack" "id:909,phase:1,deny,status:403,log"
            ';
            return 200 "clean\n";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

# HTTP/0.9: bare "GET <uri>\r\n" with no version token. nginx replies with the
# body only (no status line) for 0.9, so assert on the body.
my $clean = http("GET /foo\r\n");
like($clean, qr/clean/, 'HTTP/0.9 clean request served');

# 0.9 request that should still be inspected and blocked. HTTP/0.9 has no
# status line, so a blocked request cannot carry a 403 -- nginx just closes
# the connection without writing the location's body. Assert that positively
# (empty response) rather than merely "does not contain 'clean'", which a
# crashed worker's empty/garbled response would also satisfy.
my $bad = http("GET /attack\r\n");
is($bad, '', 'HTTP/0.9 attacking request is blocked (connection closed, no body)');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
