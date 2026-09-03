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

        # PROBE MATRIX (temporary, discriminating): each location differs in
        # exactly one dimension so the CI result isolates the cause.
        location /p_body {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQUEST_BODY "@rx one" "id:61,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /p_argspost {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS_POST:val "@rx ^one$" "id:62,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /p_argspost_ctl {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule ARGS_POST:val "@rx ^one$" "id:63,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /p_args {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS:val "@rx ^one$" "id:64,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /p_rbp {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQBODY_PROCESSOR "@rx ." "id:65,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /p_ct {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQUEST_HEADERS:Content-Type "@rx urlencoded" "id:66,phase:2,deny,log,status:403"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

    }
}
EOF

$t->run()->waitforsocket('127.0.0.1:' . port(8080));

$t->plan(6);

###############################################################################

like(http_post_form('/p_body', 'val=one'), qr/^HTTP.*403/,
    'PROBE REQUEST_BODY matches raw body');

like(http_post_form('/p_argspost', 'val=one'), qr/^HTTP.*403/,
    'PROBE ARGS_POST without ctl');

like(http_post_form('/p_argspost_ctl', 'val=one'), qr/^HTTP.*403/,
    'PROBE ARGS_POST with explicit ctl:requestBodyProcessor=URLENCODED');

like(http_post_form('/p_args', 'val=one'), qr/^HTTP.*403/,
    'PROBE ARGS (combined) matches');

like(http_post_form('/p_rbp', 'val=one'), qr/^HTTP.*403/,
    'PROBE REQBODY_PROCESSOR is non-empty');

like(http_post_form('/p_ct', 'val=one'), qr/^HTTP.*403/,
    'PROBE Content-Type header reached the engine');

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
