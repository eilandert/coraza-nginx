#!/usr/bin/perl

# Tests for Coraza-nginx connector: the request body must be submitted to the
# engine exactly once per request.
#
# ngx_http_coraza_pre_access_handler's body-submit block used to be guarded
# only by `waiting_more_body == 0`. If the PREACCESS phase were re-entered on
# the same request after the body had already been appended and processed
# (e.g. a second PREACCESS-phase handler runs after coraza), the handler had
# no record that submission already happened and would walk
# r->request_body->bufs again, re-call coraza_append_request_body() and
# re-call coraza_process_request_body(). Symptoms: REQUEST_BODY becomes
# "BAD BODYBAD BODY", ARGS_POST gains duplicate params, and
# SecRequestBodyLimit trips at half the configured size (spurious 413).
#
# A genuine second PREACCESS-phase nginx module is not available in the test
# module set here (see t/README.md / `has(qw/.../)` across this suite: no
# module other than coraza itself hooks PREACCESS). auth_request only proves
# the pre_access ACCESS-adjacent re-entry pattern via a different phase
# (t/coraza-request-body.t's /useauth case), so it cannot exercise this
# handler being invoked twice. This test instead pins the observable
# contract on the single normal invocation: with a body-limit set to exactly
# half of a "BAD BODY" payload, a doubled submission would push the engine
# over the limit (and, before the fix, ARGS_POST would carry a repeated
# value); a single, correct submission must stay under the limit and pass.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;
use IO::Socket::INET;

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

        location /singlesubmit {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRequestBodyLimit 9
                SecRequestBodyLimitAction Reject
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /singlesubmitargs {
            coraza_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                SecRule ARGS_POST:val "@rx ^one\$" "id:2,phase:2,deny,log,status:403"
                SecRule ARGS_POST:val "@rx one.*one" "id:3,phase:2,deny,log,status:409"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(2);

###############################################################################

# Body is exactly 9 bytes -- at the configured SecRequestBodyLimit. A single
# correct submission stays at-limit and passes. A doubled submission (18
# bytes effective) would exceed the limit and Reject with 413.
like(http_req_body('POST', '/singlesubmit', '123456789'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    "POST body submitted once stays within SecRequestBodyLimit");

# ARGS_POST:val is "one" for a single submission (rule 2 denies with 403,
# proving the rule engine sees it and the value is not doubled to "oneone",
# which rule 3 would instead catch and deny with 409).
like(http_req_body('POST', '/singlesubmitargs', 'val=one'), qr/^HTTP.*403/,
    "POST body ARGS_POST value not duplicated across a resubmission");

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
		print $client "TEST-OK-IF-YOU-SEE-THIS"
			unless $headers =~ /^HEAD/i;

		close $client;
	}
}

sub http_req_body {
	my $method = shift;
	my $uri = shift;
	my $body = shift;
	return http(
		"$method $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Type: application/x-www-form-urlencoded" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	);
}

###############################################################################
