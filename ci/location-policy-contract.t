#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use Text::ParseWords qw(shellwords);
use Digest::SHA;

my $root = "$FindBin::Bin/..";
my $nginx = $ENV{TEST_NGINX_SOURCE};
BAIL_OUT('TEST_NGINX_SOURCE must name a configured nginx source tree')
    unless defined $nginx && -f "$nginx/objs/ngx_auto_config.h";
my $coraza = $ENV{TEST_LIBCORAZA_INCLUDE} // '/usr/include';
BAIL_OUT('TEST_LIBCORAZA_INCLUDE must contain coraza/coraza.h')
    unless -f "$coraza/coraza/coraza.h";
my $tmp = tempdir(CLEANUP => 1);
open my $source, '<', "$root/src/ngx_http_coraza_module.c" or die $!;
my $code = do { local $/; <$source> };
close $source or die $!;

# Registration assertions are source-contract lint, not nginx runtime coverage.
my ($init) = $code =~ /(static ngx_int_t\s+ngx_http_coraza_init\(ngx_conf_t \*cf\)\s*\{.*?^\})/msg;
defined $init or BAIL_OUT('module initializer not found');
unlike($init, qr/NGX_HTTP_REWRITE_PHASE/, 'contract lint: no transaction binding in rewrite');
like($init, qr/NGX_HTTP_PREACCESS_PHASE.*?\*h_preaccess = ngx_http_coraza_pre_access_handler/s,
    'contract lint: stable preaccess handler is registered');
open my $extracted, '>', "$tmp/location-lifecycle.inc" or die $!;
for my $signature (
    qr/void ngx_http_coraza_cleanup\(void \*data\)/,
    qr/ngx_inline ngx_http_coraza_ctx_t \*\s*ngx_http_coraza_create_ctx\(ngx_http_request_t \*r\)/,
) {
    my @functions = $code =~ /($signature\s*\{.*?^\})/msg;
    @functions == 1 or BAIL_OUT("expected one function for $signature");
    # ngx_inline is a linkage hint; the fixture needs an externally callable
    # constructor definition when compiled independently at every optimization.
    $functions[0] =~ s/^ngx_inline //;
    print {$extracted} "$functions[0]\n" or die $!;
}
close $extracted or die $!;
my @includes = map { "-I$_" } ($tmp, "$root/src", $coraza,
    map { "$nginx/$_" } qw(objs src/core src/event src/event/modules
        src/event/quic src/os/unix src/http src/http/modules src/http/v2 src/http/v3));
my @cc = shellwords($ENV{CC} // 'cc');
my @flags = shellwords($ENV{CFLAGS} // '');
my $binary = "$tmp/location-policy-contract";
# Generated libcoraza headers contain unused static cgo callbacks. Match the
# module build's warning policy while keeping all other warnings fatal.
my @cmd = (@cc, '-std=c11', '-O2', '-Wall', '-Werror', '-Wno-unused-function',
    '-ffunction-sections', '-fdata-sections', @flags, @includes,
    "$FindBin::Bin/location-policy/contract.c", '-Wl,--gc-sections', '-o', $binary);
is(system(@cmd), 0, 'actual handlers and constructor compile against nginx/libcoraza headers')
    or BAIL_OUT('compile failed');
my @info = stat $binary;
my $sha = Digest::SHA->new(256)->addfile($binary)->hexdigest;
diag("binary=$binary mtime=$info[9] size=$info[7] sha256=$sha");
for my $case (qw(different same on-off off-on off-off main-waf id
    id-error no-waf allocation connection early early-off early-engine-error
    early-no-waf early-allocation early-connection early-interruption early-redirect
    early-cleanup resume redirect redirect-off logged
    header-once subrequest log-close log-id log-off log-engine-error
    log-interruption log-allocation log-no-waf log-cleanup)) {
    is(system($binary, $case), 0, $case);
}
done_testing();
