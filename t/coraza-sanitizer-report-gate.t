#!/usr/bin/env perl

use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;

my $checker = 'tools/check-sanitizer-reports.sh';
my $logs = tempdir(CLEANUP => 1);

is(system('bash', $checker, $logs), 0, 'empty report directory passes');

my $missing = `bash '$checker' '$logs/missing' 2>&1`;
is($? >> 8, 2, 'missing report directory fails closed');
like($missing, qr/^FAIL: sanitizer log directory does not exist:/m,
    'missing-directory failure is actionable');

open my $asan, '>', "$logs/asan.123" or die "open asan report: $!";
print {$asan} "ERROR: AddressSanitizer: heap-use-after-free\n";
close $asan or die "close asan report: $!";

my $asan_output = `bash '$checker' '$logs' 2>&1`;
is($? >> 8, 1, 'ASan report still makes the detector fail');
like($asan_output, qr/^FAIL: ASan report:/m, 'failure identifies the ASan report');
like($asan_output, qr/ERROR: AddressSanitizer: heap-use-after-free/,
    'failure includes the ASan diagnostic');
unlink "$logs/asan.123" or die "unlink asan report: $!";

open my $ubsan, '>', "$logs/ubsan.123" or die "open ubsan report: $!";
print {$ubsan} "runtime error: signed integer overflow\n";
close $ubsan or die "close ubsan report: $!";

my $output = `bash '$checker' '$logs' 2>&1`;
is($? >> 8, 1, 'UBSan report makes the detector fail');
like($output, qr/^FAIL: UBSan report:/m, 'failure identifies the UBSan report');
like($output, qr/runtime error: signed integer overflow/, 'failure includes the diagnostic');

unlink "$logs/ubsan.123" or die "unlink ubsan report: $!";
open my $other, '>', "$logs/nginx.log" or die "open unrelated log: $!";
close $other or die "close unrelated log: $!";
is(system('bash', $checker, $logs), 0, 'unrelated logs do not trip the gate');

done_testing;
