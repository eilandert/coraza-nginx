package coraza_crash_check;

# Shared worker-crash detector for the coraza-nginx prove suite.
#
# A test that only checks the HTTP status/body of the last request can pass
# even when the worker segfaulted mid-run and was silently respawned, or when
# an ASan build already unwound and logged a report -- neither shows up in the
# response. Every file that starts nginx must therefore also grep error.log
# for a crash signature before Test::Nginx tears the instance down.
#
# CI flattens this repo's t/ into nginx-tests' own directory with a
# non-recursive `cp ../t/* .` (see .github/workflows/build-test.yml), so this
# module MUST stay a flat file directly under t/ -- a t/lib/ subdirectory
# would silently fail to ship (cp refuses to copy directories without -r,
# and the workflow step runs under `set -euo pipefail`, so that would abort
# the whole prove run rather than just dropping the helper).
#
# Usage, right before/instead of the file's own $t->stop():
#
#   use lib '.';
#   use coraza_crash_check;
#
#   coraza_crash_check::assert_no_crash($t, 'no crash from <scenario>');
#
# assert_no_crash() calls $t->stop() itself (Test::Nginx::stop is safe to
# call more than once), then runs exactly one Test::More assertion, so add 1
# to the file's plan() count for each call.

use warnings;
use strict;

use Test::More;

# Matches what the three original crash-checking tests looked for
# (coraza-empty-header-value.t, coraza-request-body-chunked.t,
# coraza-deleted-headers.t), widened slightly to catch an nginx [emerg]
# worker-exited-on-signal log line too.
our $CRASH_RE = qr/\[emerg\].*signal|signal 11|SIGSEGV|SIGABRT|SIGBUS|AddressSanitizer/;

sub assert_no_crash {
	my ($t, $name) = @_;

	$name = 'no worker crash in error.log' unless defined $name;

	$t->stop();

	unlike($t->read_file('error.log'), $CRASH_RE, $name);
}

1;
