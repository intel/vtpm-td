#!/usr/bin/perl -w
#
# This script runs the OpenSSL Configure script, then processes the
# resulting file list into build/openssl_src.rs file
# and also copies of opensslconf.h and dso_conf.h
#
# This only needs to be done once by a developer when updating to a
# new vesion of OpenSSL.

use strict;
use Cwd;
use File::Copy;
use File::Basename;
use File::Path qw(make_path remove_tree);
use Text::Tabs;

my $openss_sources_template;
my $OPENSSL_PATH;
my @file_context;

BEGIN {
    $openss_sources_template = "openssl_sources.rs.template";
    open(FD, "<" . $openss_sources_template) ||
        die "Cannot open \"" . $openss_sources_template . "\"!";
    @file_context = (<FD>);
    close(FD) ||
        die "Cannot close \"" . $openss_sources_template . "\"!";
    $OPENSSL_PATH = "../openssl";
    my $OPENSSL_CONFIGURE = $OPENSSL_PATH . "/Configure";
    system(
        $OPENSSL_CONFIGURE,
        "UEFI",
        "no-afalgeng",
        "no-asan",
        "no-asm",
        "no-async",
        "no-autoalginit",
        "no-autoerrinit",
        "no-autoload-config",
        "no-bf",
        "no-blake2",
        "no-capieng",
        "no-cast",
        "no-chacha",
        "no-cms",
        "no-ct",
        "no-deprecated",
        "no-dgram",
        "no-dsa",
        "no-dynamic-engine",
        "no-engine",
        "no-err",
        "no-filenames",
        "no-gost",
        "no-hw",
        "no-idea",
        "no-md4",
        "no-mdc2",
        "no-pic",
        "no-ocb",
        "no-poly1305",
        "no-posix-io",
        "no-rc2",
        "no-rfc3779",
        "no-rmd160",
        "no-seed",
        "no-scrypt",
        "no-sock",
        "no-srp",
        "no-ssl",
        "no-stdio",
        "no-threads",
        "no-ts",
        "no-whirlpool",
        "no-comp",
"no-dso",
"no-hw-padlock",
"no-makedepend",
"no-multiblock",
"no-ocsp",
"no-shared",
"no-srtp",
"no-tests",
"no-ui-console",
"no-ssl3",
"no-tls",
"no-aria",
"no-tls1-method",
"no-tls1_1-method",
"no-tls1_2-method",
"no-dtls1-method",
"no-dtls1_2-method",
"no-rdrand",
        "--with-rand-seed=none"
    )== 0 ||
        die "OpenSSL Configure failed!\n";

    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/opensslv.h.in > conf-include/openssl/opensslv.h"
    )== 0 ||
        die "Failed to generate opensslv.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/crypto.h.in > conf-include/openssl/crypto.h"
    )== 0 ||
        die "Failed to generate crypto.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/safestack.h.in > conf-include/openssl/safestack.h"
    )== 0 ||
        die "Failed to generate safestack.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/bio.h.in > conf-include/openssl/bio.h"
    )== 0 ||
        die "Failed to generate bio.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/asn1.h.in > conf-include/openssl/asn1.h"
    )== 0 ||
        die "Failed to generate asn1.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/asn1t.h.in > conf-include/openssl/asn1t.h"
    )== 0 ||
        die "Failed to generate asn1t.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/cmp.h.in > conf-include/openssl/cmp.h"
    )== 0 ||
        die "Failed to generate cmp.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/cms.h.in > conf-include/openssl/cms.h"
    )== 0 ||
        die "Failed to generate cms.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/conf.h.in > conf-include/openssl/conf.h"
    )== 0 ||
        die "Failed to generate conf.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/crmf.h.in > conf-include/openssl/crmf.h"
    )== 0 ||
        die "Failed to generate crmf.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/ct.h.in > conf-include/openssl/ct.h"
    )== 0 ||
        die "Failed to generate ct.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/err.h.in > conf-include/openssl/err.h"
    )== 0 ||
        die "Failed to generate err.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/ess.h.in > conf-include/openssl/ess.h"
    )== 0 ||
        die "Failed to generate ess.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/fipskey.h.in > conf-include/openssl/fipskey.h"
    )== 0 ||
        die "Failed to generate fipskey.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/lhash.h.in > conf-include/openssl/lhash.h"
    )== 0 ||
        die "Failed to generate lhash.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/ocsp.h.in > conf-include/openssl/ocsp.h"
    )== 0 ||
        die "Failed to generate ocsp.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/pkcs7.h.in > conf-include/openssl/pkcs7.h"
    )== 0 ||
        die "Failed to generate pkcs7.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/pkcs12.h.in > conf-include/openssl/pkcs12.h"
    )== 0 ||
        die "Failed to generate pkcs12.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/srp.h.in > conf-include/openssl/srp.h"
    )== 0 ||
        die "Failed to generate srp.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/ssl.h.in > conf-include/openssl/ssl.h"
    )== 0 ||
        die "Failed to generate ssl.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/ui.h.in > conf-include/openssl/ui.h"
    )== 0 ||
        die "Failed to generate ui.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/x509_vfy.h.in > conf-include/openssl/x509_vfy.h"
    )== 0 ||
        die "Failed to generate x509_vfy.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/x509.h.in > conf-include/openssl/x509.h"
    )== 0 ||
        die "Failed to generate x509.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/x509v3.h.in > conf-include/openssl/x509v3.h"
    )== 0 ||
        die "Failed to generate x509v3.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/crypto/bn_conf.h.in > conf-include/crypto/bn_conf.h"
    ) == 0 ||
        die "Failed to generate bn_conf.h!\n";

    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/openssl/configuration.h.in > conf-include/openssl/configuration.h"
    )== 0 ||
        die "Failed to generate configuration.h!\n";
    system(
        "perl -I. -Mconfigdata ../openssl/util/dofile.pl ../openssl/include/crypto/dso_conf.h.in > conf-include/crypto/dso_conf.h"
    ) == 0 ||
        die "Failed to generate dso_conf.h!\n";

    push @INC, ".";
}

#
# Retrieve file lists from OpenSSL configdata
#
use configdata qw/%unified_info/;
use configdata qw/%config/;
use configdata qw/%target/;

#
# Collect build flags from configdata
#
my $flags = "";
foreach my $f (@{$config{lib_defines}}) {
    $flags .= " -D$f";
}

my @cryptofilelist = ();
my @sslfilelist = ();

foreach my $product ((@{$unified_info{libraries}},
                      @{$unified_info{engines}})) {
    foreach my $o (@{$unified_info{sources}->{$product}}) {
        foreach my $s (@{$unified_info{sources}->{$o}}) {
            # No need to add unused files in UEFI.
            # So it can reduce porting time, compile time, library size.
            next if $s =~ "crypto/bio/b_print.c";
            next if $s =~ "crypto/rand/randfile.c";
            next if $s =~ "crypto/store/";
            next if $s =~ "crypto/err/err_all.c";
            next if $s =~ "crypto/aes/aes_ecb.c";

            if ($product =~ "libssl") {
                push @sslfilelist, $s . "\r\n";
                next;
            }
            push @cryptofilelist, "    &\"" . substr($s,11,10000) . "\",\r\n";

        }
    }
}

# foreach my $s (@cryptofilelist) {
#     print $s
# }


print "\n--> Generating openssl_sources.rs ... ";

my $subbing = 0;
my @new_file_context;
foreach (@file_context) {
    if ( $_ =~ "// GENERATE_START" ) {
        push @new_file_context, $_, @cryptofilelist;
        $subbing = 1;
        next;
    }
    if ( $_ =~ "// GENERATE_END" ) {
        push @new_file_context, $_;
        $subbing = 0;
        next;
    }

    push @new_file_context, $_
        unless ($subbing);
}

# print @new_file_context

my $new_openssl_srcs_file = "openssl_sources.rs";
open( FD, ">" . $new_openssl_srcs_file ) ||
    die $new_openssl_srcs_file;
print( FD @new_file_context ) ||
    die $new_openssl_srcs_file;
close(FD) ||
    die $new_openssl_srcs_file;
print "Done!\n";

print "\nProcessing Files Done!\n";
