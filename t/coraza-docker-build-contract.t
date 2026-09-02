#!/usr/bin/perl

use warnings;
use strict;

use Test::More;
use FindBin;

my $root = "$FindBin::Bin/..";
my $dockerfile = slurp("$root/Dockerfile");
my $versions = slurp("$root/.github/versions.env");

my ($docker_libcoraza) = $dockerfile =~ /^ARG LIBCORAZA_VERSION=(v\d+\.\d+\.\d+)$/m;
my ($pinned_libcoraza) = $versions =~ /^LIBCORAZA_VERSION=(v\d+\.\d+\.\d+)$/m;
my ($docker_libcoraza_sha) = $dockerfile =~ /^ARG LIBCORAZA_SHA256=([0-9a-f]{64})$/m;
my ($pinned_libcoraza_sha) = $versions =~ /^LIBCORAZA_SHA256=([0-9a-f]{64})$/m;
my ($docker_tests_ref) = $dockerfile =~ /^ARG NGINX_TESTS_REF=([0-9a-f]{40})$/m;
my ($pinned_tests_ref) = $versions =~ /^NGINX_TESTS_REF=([0-9a-f]{40})$/m;
my ($docker_tests_sha) = $dockerfile =~ /^ARG NGINX_TESTS_SHA256=([0-9a-f]{64})$/m;
my ($pinned_tests_sha) = $versions =~ /^NGINX_TESTS_SHA256=([0-9a-f]{64})$/m;

is($docker_libcoraza, $pinned_libcoraza,
    'Docker image builds the centrally pinned libcoraza release');
is($docker_libcoraza_sha, $pinned_libcoraza_sha,
    'Docker image verifies the centrally pinned libcoraza archive');
is($docker_tests_ref, $pinned_tests_ref,
    'Docker image runs the centrally pinned nginx-tests revision');
is($docker_tests_sha, $pinned_tests_sha,
    'Docker image verifies the pinned nginx-tests archive');

like($dockerfile, qr/^\s*prove -v coraza\*\.t\s*&&\s*\\$/m,
    'Docker build runs the connector test suite');
unlike($dockerfile, qr/prove -v coraza\*\.t[^\n]*(?:\|\|\s*true|;\s*true)/,
    'Docker build propagates connector test failures');

done_testing();

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/ = undef;
    return <$fh>;
}
