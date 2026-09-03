#!/usr/bin/perl

# Tests for Coraza-nginx connector: ARGS_POST matching.
#
# No existing test demonstrates a rule actually matching against ARGS_POST.
# t/coraza-request-body.t's /nobodyaccess location has an ARGS_POST rule, but
# every probe against it is a benign pass -- it never proves the rule can
# fire. t/coraza-request-body-single-submit.t attempted an ARGS_POST-based
# oracle and found the rule did not match in CI; the root cause was a
# malformed probe body (it omitted the "=" from the urlencoded pair, so
# nginx/Coraza never parsed a POST arg named "val" out of it in the first
# place) -- not a connector defect. This test sends a well-formed
# "val=one"/"val=two" pair with the required Content-Type and asserts the
# rule matches and blocks the former while a benign control passes.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        coraza on;

        location /argspost {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS_POST:val "@rx ^one$" "id:51,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }
    }
}
EOF

$t->run()->waitforsocket('127.0.0.1:' . port(8080));

$t->plan(2);

###############################################################################

like(http_post_form('/argspost', 'val=one'), qr/^HTTP.*403/,
    'ARGS_POST:val matches a well-formed urlencoded pair and blocks');

like(http_post_form('/argspost', 'val=two'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    'ARGS_POST:val benign control (non-matching value) passes');

###############################################################################

sub http_post_form {
	my ($uri, $body) = @_;
	return http(
		"POST $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Type: application/x-www-form-urlencoded" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

###############################################################################
