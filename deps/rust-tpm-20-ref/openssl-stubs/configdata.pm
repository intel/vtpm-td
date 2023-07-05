#! /usr/bin/env perl

package configdata;

use strict;
use warnings;

use Exporter;
#use vars qw(@ISA @EXPORT);
our @ISA = qw(Exporter);
our @EXPORT = qw(%config %target %disabled %withargs %unified_info @disablables);

our %config = (
  AR => "llvm-ar",
  ARFLAGS => [ "r" ],
  CC => "clang",
  CFLAGS => [ "-Wall -Werror -Wno-format -target x86_64-unknown-none -fPIC         -nostdlib -nostdlibinc -ffreestanding -Istd-include -Iconf-include         -Iarch/x86_64 -include CrtLibSupport.h -std=c99" ],
  CPPDEFINES => [  ],
  CPPFLAGS => [  ],
  CPPINCLUDES => [  ],
  CXXFLAGS => [  ],
  HASHBANGPERL => "/usr/bin/env perl",
  LDFLAGS => [  ],
  LDLIBS => [  ],
  PERL => "/usr/bin/perl",
  RANLIB => "ranlib",
  RC => "windres",
  RCFLAGS => [  ],
  api => "1.1.0",
  b32 => "1",
  b64 => "0",
  b64l => "0",
  bn_ll => "0",
  build_file => "Makefile",
  build_file_templates => [ "../openssl/Configurations/common0.tmpl", "../openssl/Configurations/unix-Makefile.tmpl", "../openssl/Configurations/common.tmpl" ],
  build_infos => [ "../openssl/build.info", "../openssl/crypto/build.info", "../openssl/ssl/build.info", "../openssl/apps/build.info", "../openssl/test/build.info", "../openssl/util/build.info", "../openssl/tools/build.info", "../openssl/fuzz/build.info", "../openssl/crypto/objects/build.info", "../openssl/crypto/md5/build.info", "../openssl/crypto/sha/build.info", "../openssl/crypto/hmac/build.info", "../openssl/crypto/siphash/build.info", "../openssl/crypto/sm3/build.info", "../openssl/crypto/des/build.info", "../openssl/crypto/aes/build.info", "../openssl/crypto/rc4/build.info", "../openssl/crypto/camellia/build.info", "../openssl/crypto/sm4/build.info", "../openssl/crypto/modes/build.info", "../openssl/crypto/bn/build.info", "../openssl/crypto/ec/build.info", "../openssl/crypto/rsa/build.info", "../openssl/crypto/dh/build.info", "../openssl/crypto/sm2/build.info", "../openssl/crypto/dso/build.info", "../openssl/crypto/buffer/build.info", "../openssl/crypto/bio/build.info", "../openssl/crypto/stack/build.info", "../openssl/crypto/lhash/build.info", "../openssl/crypto/rand/build.info", "../openssl/crypto/err/build.info", "../openssl/crypto/evp/build.info", "../openssl/crypto/asn1/build.info", "../openssl/crypto/pem/build.info", "../openssl/crypto/x509/build.info", "../openssl/crypto/x509v3/build.info", "../openssl/crypto/conf/build.info", "../openssl/crypto/txt_db/build.info", "../openssl/crypto/pkcs7/build.info", "../openssl/crypto/pkcs12/build.info", "../openssl/crypto/ui/build.info", "../openssl/crypto/cmac/build.info", "../openssl/crypto/async/build.info", "../openssl/crypto/kdf/build.info", "../openssl/crypto/store/build.info", "../openssl/test/ossl_shim/build.info" ],
  build_type => "release",
  builddir => ".",
  cflags => [  ],
  conf_files => [ "../openssl/Configurations/00-base-templates.conf", "../openssl/Configurations/10-main.conf" ],
  cppflags => [  ],
  cxxflags => [  ],
  defines => [ "NDEBUG", "OPENSSL_API_COMPAT=0x10100000L" ],
  dirs => [ "crypto", "ssl", "apps", "test", "util", "tools", "fuzz" ],
  dynamic_engines => "0",
  engdirs => [  ],
  ex_libs => [  ],
  export_var_as_fn => "0",
  includes => [  ],
  lflags => [  ],
  libdir => "",
  major => "1",
  minor => "1.1",
  openssl_algorithm_defines => [ "OPENSSL_NO_ARIA", "OPENSSL_NO_BF", "OPENSSL_NO_BLAKE2", "OPENSSL_NO_CAST", "OPENSSL_NO_CHACHA", "OPENSSL_NO_CMS", "OPENSSL_NO_COMP", "OPENSSL_NO_CT", "OPENSSL_NO_DSA", "OPENSSL_NO_IDEA", "OPENSSL_NO_MD2", "OPENSSL_NO_MD4", "OPENSSL_NO_MDC2", "OPENSSL_NO_OCSP", "OPENSSL_NO_POLY1305", "OPENSSL_NO_RC2", "OPENSSL_NO_RC5", "OPENSSL_NO_RMD160", "OPENSSL_NO_SEED", "OPENSSL_NO_SRP", "OPENSSL_NO_TS", "OPENSSL_NO_WHIRLPOOL" ],
  openssl_api_defines => [ "OPENSSL_MIN_API=0x10100000L" ],
  openssl_other_defines => [ "OPENSSL_RAND_SEED_NONE", "OPENSSL_NO_AFALGENG", "OPENSSL_NO_APPS", "OPENSSL_NO_ASAN", "OPENSSL_NO_ASM", "OPENSSL_NO_ASYNC", "OPENSSL_NO_AUTOALGINIT", "OPENSSL_NO_AUTOERRINIT", "OPENSSL_NO_AUTOLOAD_CONFIG", "OPENSSL_NO_CAPIENG", "OPENSSL_NO_CRYPTO_MDEBUG", "OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE", "OPENSSL_NO_DEPRECATED", "OPENSSL_NO_DEVCRYPTOENG", "OPENSSL_NO_DGRAM", "OPENSSL_NO_DSO", "OPENSSL_NO_DTLS", "OPENSSL_NO_DTLS1", "OPENSSL_NO_DTLS1_METHOD", "OPENSSL_NO_DTLS1_2", "OPENSSL_NO_DTLS1_2_METHOD", "OPENSSL_NO_EC_NISTP_64_GCC_128", "OPENSSL_NO_EGD", "OPENSSL_NO_ENGINE", "OPENSSL_NO_ERR", "OPENSSL_NO_EXTERNAL_TESTS", "OPENSSL_NO_FILENAMES", "OPENSSL_NO_FUZZ_AFL", "OPENSSL_NO_FUZZ_LIBFUZZER", "OPENSSL_NO_GOST", "OPENSSL_NO_HEARTBEATS", "OPENSSL_NO_HW", "OPENSSL_NO_HW_PADLOCK", "OPENSSL_NO_MSAN", "OPENSSL_NO_MULTIBLOCK", "OPENSSL_NO_OCB", "OPENSSL_NO_POSIX_IO", "OPENSSL_NO_RDRAND", "OPENSSL_NO_RFC3779", "OPENSSL_NO_SCRYPT", "OPENSSL_NO_SCTP", "OPENSSL_NO_SOCK", "OPENSSL_NO_SRTP", "OPENSSL_NO_SSL_TRACE", "OPENSSL_NO_SSL3", "OPENSSL_NO_SSL3_METHOD", "OPENSSL_NO_STDIO", "OPENSSL_NO_TESTS", "OPENSSL_NO_TLS", "OPENSSL_NO_TLS1", "OPENSSL_NO_TLS1_METHOD", "OPENSSL_NO_TLS1_1", "OPENSSL_NO_TLS1_1_METHOD", "OPENSSL_NO_TLS1_2", "OPENSSL_NO_TLS1_2_METHOD", "OPENSSL_NO_TLS1_3", "OPENSSL_NO_UBSAN", "OPENSSL_NO_UI_CONSOLE", "OPENSSL_NO_UNIT_TEST", "OPENSSL_NO_WEAK_SSL_CIPHERS", "OPENSSL_NO_DYNAMIC_ENGINE" ],
  openssl_sys_defines => [ "OPENSSL_SYS_UEFI" ],
  openssl_thread_defines => [  ],
  openssldir => "",
  options => "--with-rand-seed=none no-afalgeng no-apps no-aria no-asan no-asm no-async no-autoalginit no-autoerrinit no-autoload-config no-bf no-blake2 no-buildtest-c++ no-capieng no-cast no-chacha no-cms no-comp no-crypto-mdebug no-crypto-mdebug-backtrace no-ct no-deprecated no-devcryptoeng no-dgram no-dsa no-dso no-dtls no-dtls1 no-dtls1-method no-dtls1_2 no-dtls1_2-method no-dynamic-engine no-ec_nistp_64_gcc_128 no-egd no-engine no-err no-external-tests no-filenames no-fuzz-afl no-fuzz-libfuzzer no-gost no-heartbeats no-hw no-hw-padlock no-idea no-makedepend no-md2 no-md4 no-mdc2 no-msan no-multiblock no-ocb no-ocsp no-pic no-poly1305 no-posix-io no-rc2 no-rc5 no-rdrand no-rfc3779 no-rmd160 no-scrypt no-sctp no-seed no-shared no-sock no-srp no-srtp no-ssl-trace no-ssl3 no-ssl3-method no-stdio no-tests no-threads no-tls no-tls1 no-tls1-method no-tls1_1 no-tls1_1-method no-tls1_2 no-tls1_2-method no-tls1_3 no-ts no-ubsan no-ui-console no-unit-test no-weak-ssl-ciphers no-whirlpool no-zlib no-zlib-dynamic",
  perl_archname => "x86_64-linux-thread-multi",
  perl_cmd => "/usr/bin/perl",
  perl_version => "5.26.3",
  perlargv => [ "UEFI", "no-afalgeng", "no-asan", "no-asm", "no-async", "no-autoalginit", "no-autoerrinit", "no-autoload-config", "no-bf", "no-blake2", "no-capieng", "no-cast", "no-chacha", "no-cms", "no-ct", "no-deprecated", "no-dgram", "no-dsa", "no-dynamic-engine", "no-engine", "no-err", "no-filenames", "no-gost", "no-hw", "no-idea", "no-md4", "no-mdc2", "no-pic", "no-ocb", "no-poly1305", "no-posix-io", "no-rc2", "no-rfc3779", "no-rmd160", "no-seed", "no-scrypt", "no-sock", "no-srp", "no-ssl", "no-stdio", "no-threads", "no-ts", "no-whirlpool", "no-comp", "no-dso", "no-hw-padlock", "no-makedepend", "no-multiblock", "no-ocsp", "no-shared", "no-srtp", "no-tests", "no-ui-console", "no-ssl3", "no-tls", "no-aria", "no-tls1-method", "no-tls1_1-method", "no-tls1_2-method", "no-dtls1-method", "no-dtls1_2-method", "no-rdrand", "--with-rand-seed=none" ],
  perlenv => {
      "AR" => "llvm-ar",
      "ARFLAGS" => undef,
      "AS" => undef,
      "ASFLAGS" => undef,
      "BUILDFILE" => undef,
      "CC" => "clang",
      "CFLAGS" => "-Wall -Werror -Wno-format -target x86_64-unknown-none -fPIC         -nostdlib -nostdlibinc -ffreestanding -Istd-include -Iconf-include         -Iarch/x86_64 -include CrtLibSupport.h -std=c99",
      "CPP" => undef,
      "CPPDEFINES" => undef,
      "CPPFLAGS" => undef,
      "CPPINCLUDES" => undef,
      "CROSS_COMPILE" => undef,
      "CXX" => undef,
      "CXXFLAGS" => undef,
      "HASHBANGPERL" => undef,
      "LD" => undef,
      "LDFLAGS" => undef,
      "LDLIBS" => undef,
      "MT" => undef,
      "MTFLAGS" => undef,
      "OPENSSL_LOCAL_CONFIG_DIR" => undef,
      "PERL" => undef,
      "RANLIB" => undef,
      "RC" => undef,
      "RCFLAGS" => undef,
      "RM" => undef,
      "WINDRES" => undef,
      "__CNF_CFLAGS" => undef,
      "__CNF_CPPDEFINES" => undef,
      "__CNF_CPPFLAGS" => undef,
      "__CNF_CPPINCLUDES" => undef,
      "__CNF_CXXFLAGS" => undef,
      "__CNF_LDFLAGS" => undef,
      "__CNF_LDLIBS" => undef,
  },
  prefix => "",
  processor => "",
  rc4_int => "unsigned int",
  sdirs => [ "objects", "md5", "sha", "hmac", "siphash", "sm3", "des", "aes", "rc4", "camellia", "sm4", "modes", "bn", "ec", "rsa", "dh", "sm2", "dso", "buffer", "bio", "stack", "lhash", "rand", "err", "evp", "asn1", "pem", "x509", "x509v3", "conf", "txt_db", "pkcs7", "pkcs12", "ui", "cmac", "async", "kdf", "store" ],
  shlib_major => "1",
  shlib_minor => "1",
  shlib_version_history => "",
  shlib_version_number => "1.1",
  sourcedir => "../openssl",
  target => "UEFI",
  tdirs => [ "ossl_shim" ],
  version => "1.1.1u",
  version_num => "0x1010115fL",
);

our %target = (
  AR => "ar",
  ARFLAGS => "r",
  CC => "cc",
  CFLAGS => "-O",
  HASHBANGPERL => "/usr/bin/env perl",
  RANLIB => "ranlib",
  RC => "windres",
  _conf_fname_int => [ "../openssl/Configurations/00-base-templates.conf", "../openssl/Configurations/00-base-templates.conf", "../openssl/Configurations/10-main.conf", "../openssl/Configurations/shared-info.pl" ],
  aes_asm_src => "aes_core.c aes_cbc.c",
  aes_obj => "aes_core.o aes_cbc.o",
  apps_aux_src => "",
  apps_init_src => "",
  apps_obj => "",
  bf_asm_src => "bf_enc.c",
  bf_obj => "bf_enc.o",
  bn_asm_src => "bn_asm.c",
  bn_obj => "bn_asm.o",
  build_file => "Makefile",
  build_scheme => [ "unified", "unix" ],
  cast_asm_src => "c_enc.c",
  cast_obj => "c_enc.o",
  cflags => "",
  chacha_asm_src => "chacha_enc.c",
  chacha_obj => "chacha_enc.o",
  cmll_asm_src => "camellia.c cmll_misc.c cmll_cbc.c",
  cmll_obj => "camellia.o cmll_misc.o cmll_cbc.o",
  cppflags => "",
  cpuid_asm_src => "mem_clr.c",
  cpuid_obj => "mem_clr.o",
  defines => [  ],
  des_asm_src => "des_enc.c fcrypt_b.c",
  des_obj => "des_enc.o fcrypt_b.o",
  disable => [  ],
  dso_extension => ".so",
  ec_asm_src => "",
  ec_obj => "",
  enable => [  ],
  exe_extension => "",
  includes => [  ],
  keccak1600_asm_src => "keccak1600.c",
  keccak1600_obj => "keccak1600.o",
  lflags => "",
  lib_cflags => "",
  lib_cppflags => "-DL_ENDIAN",
  lib_defines => [  ],
  md5_asm_src => "",
  md5_obj => "",
  modes_asm_src => "",
  modes_obj => "",
  module_cflags => "",
  module_cppflags => "",
  module_cxxflags => "",
  module_defines => "",
  module_includes => "",
  module_ldflags => "",
  module_lflags => "",
  padlock_asm_src => "",
  padlock_obj => "",
  poly1305_asm_src => "",
  poly1305_obj => "",
  rc4_asm_src => "rc4_enc.c rc4_skey.c",
  rc4_obj => "rc4_enc.o rc4_skey.o",
  rc5_asm_src => "rc5_enc.c",
  rc5_obj => "rc5_enc.o",
  rmd160_asm_src => "",
  rmd160_obj => "",
  shared_cflag => "",
  shared_cppflag => "",
  shared_cxxflag => "",
  shared_defines => "",
  shared_extension => ".so",
  shared_extension_simple => ".so",
  shared_includes => "",
  shared_ldflag => "",
  shared_rcflag => "",
  shared_target => "",
  sys_id => "UEFI",
  template => "1",
  thread_defines => [  ],
  thread_scheme => "(unknown)",
  unistd => "<unistd.h>",
  uplink_aux_src => "",
  uplink_obj => "",
  wp_asm_src => "wp_block.c",
  wp_obj => "wp_block.o",
);

our %available_protocols = (
  tls => [ "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3" ],
  dtls => [ "dtls1", "dtls1_2" ],
);

our @disablables = (
  "afalgeng",
  "aria",
  "asan",
  "asm",
  "async",
  "autoalginit",
  "autoerrinit",
  "autoload-config",
  "bf",
  "blake2",
  "buildtest-c\\+\\+",
  "camellia",
  "capieng",
  "cast",
  "chacha",
  "cmac",
  "cms",
  "comp",
  "crypto-mdebug",
  "crypto-mdebug-backtrace",
  "ct",
  "deprecated",
  "des",
  "devcryptoeng",
  "dgram",
  "dh",
  "dsa",
  "dso",
  "dtls",
  "dynamic-engine",
  "ec",
  "ec2m",
  "ecdh",
  "ecdsa",
  "ec_nistp_64_gcc_128",
  "egd",
  "engine",
  "err",
  "external-tests",
  "filenames",
  "fuzz-libfuzzer",
  "fuzz-afl",
  "gost",
  "heartbeats",
  "hw(-.+)?",
  "idea",
  "makedepend",
  "md2",
  "md4",
  "mdc2",
  "msan",
  "multiblock",
  "nextprotoneg",
  "pinshared",
  "ocb",
  "ocsp",
  "pic",
  "poly1305",
  "posix-io",
  "psk",
  "rc2",
  "rc4",
  "rc5",
  "rdrand",
  "rfc3779",
  "rmd160",
  "scrypt",
  "sctp",
  "seed",
  "shared",
  "siphash",
  "sm2",
  "sm3",
  "sm4",
  "sock",
  "srp",
  "srtp",
  "sse2",
  "ssl",
  "ssl-trace",
  "static-engine",
  "stdio",
  "tests",
  "threads",
  "tls",
  "ts",
  "ubsan",
  "ui-console",
  "unit-test",
  "whirlpool",
  "weak-ssl-ciphers",
  "zlib",
  "zlib-dynamic",
  "ssl3",
  "ssl3-method",
  "tls1",
  "tls1-method",
  "tls1_1",
  "tls1_1-method",
  "tls1_2",
  "tls1_2-method",
  "tls1_3",
  "dtls1",
  "dtls1-method",
  "dtls1_2",
  "dtls1_2-method",
);

our %disabled = (
  "afalgeng" => "option",
  "apps" => "cascade",
  "aria" => "option",
  "asan" => "option",
  "asm" => "option",
  "async" => "option",
  "autoalginit" => "option",
  "autoerrinit" => "option",
  "autoload-config" => "option",
  "bf" => "option",
  "blake2" => "option",
  "buildtest-c++" => "default",
  "capieng" => "option",
  "cast" => "option",
  "chacha" => "option",
  "cms" => "option",
  "comp" => "option",
  "crypto-mdebug" => "default",
  "crypto-mdebug-backtrace" => "default",
  "ct" => "option",
  "deprecated" => "option",
  "devcryptoeng" => "default",
  "dgram" => "option",
  "dsa" => "option",
  "dso" => "option",
  "dtls" => "cascade",
  "dtls1" => "option(dtls1-method)",
  "dtls1-method" => "option",
  "dtls1_2" => "option(dtls1_2-method)",
  "dtls1_2-method" => "option",
  "dynamic-engine" => "option",
  "ec_nistp_64_gcc_128" => "default",
  "egd" => "default",
  "engine" => "option",
  "err" => "option",
  "external-tests" => "default",
  "filenames" => "option",
  "fuzz-afl" => "default",
  "fuzz-libfuzzer" => "default",
  "gost" => "option",
  "heartbeats" => "default",
  "hw" => "option",
  "hw-padlock" => "option",
  "idea" => "option",
  "makedepend" => "option",
  "md2" => "default",
  "md4" => "option",
  "mdc2" => "option",
  "msan" => "default",
  "multiblock" => "option",
  "ocb" => "option",
  "ocsp" => "option",
  "pic" => "no-shared-target",
  "poly1305" => "option",
  "posix-io" => "option",
  "rc2" => "option",
  "rc5" => "default",
  "rdrand" => "option",
  "rfc3779" => "option",
  "rmd160" => "option",
  "scrypt" => "option",
  "sctp" => "default",
  "seed" => "option",
  "shared" => "option",
  "sock" => "option",
  "srp" => "option",
  "srtp" => "option",
  "ssl-trace" => "default",
  "ssl3" => "option(tls)",
  "ssl3-method" => "default",
  "stdio" => "option",
  "tests" => "option",
  "threads" => "option",
  "tls" => "cascade",
  "tls1" => "option(tls1-method)",
  "tls1-method" => "option",
  "tls1_1" => "option(tls1_1-method)",
  "tls1_1-method" => "option",
  "tls1_2" => "option(tls1_2-method)",
  "tls1_2-method" => "option",
  "tls1_3" => "option(tls)",
  "ts" => "option",
  "ubsan" => "default",
  "ui-console" => "option",
  "unit-test" => "default",
  "weak-ssl-ciphers" => "default",
  "whirlpool" => "option",
  "zlib" => "default",
  "zlib-dynamic" => "default",
);

our %withargs = (
);

our %unified_info = (
    "depends" =>
        {
            "" =>
                [
                    "include/crypto/bn_conf.h",
                    "include/crypto/dso_conf.h",
                    "include/openssl/opensslconf.h",
                ],
            "crypto/aes/aes-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/aes/aesni-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/aes/aest4-sparcv9.S" =>
                [
                    "../openssl/crypto/perlasm/sparcv9_modes.pl",
                ],
            "crypto/aes/vpaes-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/bn/bn-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/bn/co-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/bn/x86-gf2m.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/bn/x86-mont.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/buildinf.h" =>
                [
                    "configdata.pm",
                ],
            "crypto/camellia/cmll-x86.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/camellia/cmllt4-sparcv9.S" =>
                [
                    "../openssl/crypto/perlasm/sparcv9_modes.pl",
                ],
            "crypto/cversion.o" =>
                [
                    "crypto/buildinf.h",
                ],
            "crypto/des/crypt586.s" =>
                [
                    "../openssl/crypto/perlasm/cbc.pl",
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/des/des-586.s" =>
                [
                    "../openssl/crypto/perlasm/cbc.pl",
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/rc4/rc4-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/sha/sha1-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/sha/sha256-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/sha/sha512-586.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "crypto/x86cpuid.s" =>
                [
                    "../openssl/crypto/perlasm/x86asm.pl",
                ],
            "include/crypto/bn_conf.h" =>
                [
                    "configdata.pm",
                ],
            "include/crypto/dso_conf.h" =>
                [
                    "configdata.pm",
                ],
            "include/openssl/opensslconf.h" =>
                [
                    "configdata.pm",
                ],
            "libssl" =>
                [
                    "libcrypto",
                ],
        },
    "dirinfo" =>
        {
            "crypto" =>
                {
                    "deps" =>
                        [
                            "crypto/cpt_err.o",
                            "crypto/cryptlib.o",
                            "crypto/ctype.o",
                            "crypto/cversion.o",
                            "crypto/ebcdic.o",
                            "crypto/ex_data.o",
                            "crypto/getenv.o",
                            "crypto/init.o",
                            "crypto/mem.o",
                            "crypto/mem_clr.o",
                            "crypto/mem_dbg.o",
                            "crypto/mem_sec.o",
                            "crypto/o_dir.o",
                            "crypto/o_fips.o",
                            "crypto/o_fopen.o",
                            "crypto/o_init.o",
                            "crypto/o_str.o",
                            "crypto/o_time.o",
                            "crypto/threads_none.o",
                            "crypto/threads_pthread.o",
                            "crypto/threads_win.o",
                            "crypto/uid.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/aes" =>
                {
                    "deps" =>
                        [
                            "crypto/aes/aes_cbc.o",
                            "crypto/aes/aes_cfb.o",
                            "crypto/aes/aes_core.o",
                            "crypto/aes/aes_ecb.o",
                            "crypto/aes/aes_ige.o",
                            "crypto/aes/aes_misc.o",
                            "crypto/aes/aes_ofb.o",
                            "crypto/aes/aes_wrap.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/asn1" =>
                {
                    "deps" =>
                        [
                            "crypto/asn1/a_bitstr.o",
                            "crypto/asn1/a_d2i_fp.o",
                            "crypto/asn1/a_digest.o",
                            "crypto/asn1/a_dup.o",
                            "crypto/asn1/a_gentm.o",
                            "crypto/asn1/a_i2d_fp.o",
                            "crypto/asn1/a_int.o",
                            "crypto/asn1/a_mbstr.o",
                            "crypto/asn1/a_object.o",
                            "crypto/asn1/a_octet.o",
                            "crypto/asn1/a_print.o",
                            "crypto/asn1/a_sign.o",
                            "crypto/asn1/a_strex.o",
                            "crypto/asn1/a_strnid.o",
                            "crypto/asn1/a_time.o",
                            "crypto/asn1/a_type.o",
                            "crypto/asn1/a_utctm.o",
                            "crypto/asn1/a_utf8.o",
                            "crypto/asn1/a_verify.o",
                            "crypto/asn1/ameth_lib.o",
                            "crypto/asn1/asn1_err.o",
                            "crypto/asn1/asn1_gen.o",
                            "crypto/asn1/asn1_item_list.o",
                            "crypto/asn1/asn1_lib.o",
                            "crypto/asn1/asn1_par.o",
                            "crypto/asn1/asn_mime.o",
                            "crypto/asn1/asn_moid.o",
                            "crypto/asn1/asn_mstbl.o",
                            "crypto/asn1/asn_pack.o",
                            "crypto/asn1/bio_asn1.o",
                            "crypto/asn1/bio_ndef.o",
                            "crypto/asn1/d2i_pr.o",
                            "crypto/asn1/d2i_pu.o",
                            "crypto/asn1/evp_asn1.o",
                            "crypto/asn1/f_int.o",
                            "crypto/asn1/f_string.o",
                            "crypto/asn1/i2d_pr.o",
                            "crypto/asn1/i2d_pu.o",
                            "crypto/asn1/n_pkey.o",
                            "crypto/asn1/nsseq.o",
                            "crypto/asn1/p5_pbe.o",
                            "crypto/asn1/p5_pbev2.o",
                            "crypto/asn1/p5_scrypt.o",
                            "crypto/asn1/p8_pkey.o",
                            "crypto/asn1/t_bitst.o",
                            "crypto/asn1/t_pkey.o",
                            "crypto/asn1/t_spki.o",
                            "crypto/asn1/tasn_dec.o",
                            "crypto/asn1/tasn_enc.o",
                            "crypto/asn1/tasn_fre.o",
                            "crypto/asn1/tasn_new.o",
                            "crypto/asn1/tasn_prn.o",
                            "crypto/asn1/tasn_scn.o",
                            "crypto/asn1/tasn_typ.o",
                            "crypto/asn1/tasn_utl.o",
                            "crypto/asn1/x_algor.o",
                            "crypto/asn1/x_bignum.o",
                            "crypto/asn1/x_info.o",
                            "crypto/asn1/x_int64.o",
                            "crypto/asn1/x_long.o",
                            "crypto/asn1/x_pkey.o",
                            "crypto/asn1/x_sig.o",
                            "crypto/asn1/x_spki.o",
                            "crypto/asn1/x_val.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/async" =>
                {
                    "deps" =>
                        [
                            "crypto/async/async.o",
                            "crypto/async/async_err.o",
                            "crypto/async/async_wait.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/async/arch" =>
                {
                    "deps" =>
                        [
                            "crypto/async/arch/async_null.o",
                            "crypto/async/arch/async_posix.o",
                            "crypto/async/arch/async_win.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/bio" =>
                {
                    "deps" =>
                        [
                            "crypto/bio/b_addr.o",
                            "crypto/bio/b_dump.o",
                            "crypto/bio/b_print.o",
                            "crypto/bio/b_sock.o",
                            "crypto/bio/b_sock2.o",
                            "crypto/bio/bf_buff.o",
                            "crypto/bio/bf_lbuf.o",
                            "crypto/bio/bf_nbio.o",
                            "crypto/bio/bf_null.o",
                            "crypto/bio/bio_cb.o",
                            "crypto/bio/bio_err.o",
                            "crypto/bio/bio_lib.o",
                            "crypto/bio/bio_meth.o",
                            "crypto/bio/bss_acpt.o",
                            "crypto/bio/bss_bio.o",
                            "crypto/bio/bss_conn.o",
                            "crypto/bio/bss_dgram.o",
                            "crypto/bio/bss_fd.o",
                            "crypto/bio/bss_file.o",
                            "crypto/bio/bss_log.o",
                            "crypto/bio/bss_mem.o",
                            "crypto/bio/bss_null.o",
                            "crypto/bio/bss_sock.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/bn" =>
                {
                    "deps" =>
                        [
                            "crypto/bn/bn_add.o",
                            "crypto/bn/bn_asm.o",
                            "crypto/bn/bn_blind.o",
                            "crypto/bn/bn_const.o",
                            "crypto/bn/bn_ctx.o",
                            "crypto/bn/bn_depr.o",
                            "crypto/bn/bn_dh.o",
                            "crypto/bn/bn_div.o",
                            "crypto/bn/bn_err.o",
                            "crypto/bn/bn_exp.o",
                            "crypto/bn/bn_exp2.o",
                            "crypto/bn/bn_gcd.o",
                            "crypto/bn/bn_gf2m.o",
                            "crypto/bn/bn_intern.o",
                            "crypto/bn/bn_kron.o",
                            "crypto/bn/bn_lib.o",
                            "crypto/bn/bn_mod.o",
                            "crypto/bn/bn_mont.o",
                            "crypto/bn/bn_mpi.o",
                            "crypto/bn/bn_mul.o",
                            "crypto/bn/bn_nist.o",
                            "crypto/bn/bn_prime.o",
                            "crypto/bn/bn_print.o",
                            "crypto/bn/bn_rand.o",
                            "crypto/bn/bn_recp.o",
                            "crypto/bn/bn_shift.o",
                            "crypto/bn/bn_sqr.o",
                            "crypto/bn/bn_sqrt.o",
                            "crypto/bn/bn_srp.o",
                            "crypto/bn/bn_word.o",
                            "crypto/bn/bn_x931p.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/buffer" =>
                {
                    "deps" =>
                        [
                            "crypto/buffer/buf_err.o",
                            "crypto/buffer/buffer.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/camellia" =>
                {
                    "deps" =>
                        [
                            "crypto/camellia/camellia.o",
                            "crypto/camellia/cmll_cbc.o",
                            "crypto/camellia/cmll_cfb.o",
                            "crypto/camellia/cmll_ctr.o",
                            "crypto/camellia/cmll_ecb.o",
                            "crypto/camellia/cmll_misc.o",
                            "crypto/camellia/cmll_ofb.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/cmac" =>
                {
                    "deps" =>
                        [
                            "crypto/cmac/cm_ameth.o",
                            "crypto/cmac/cm_pmeth.o",
                            "crypto/cmac/cmac.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/conf" =>
                {
                    "deps" =>
                        [
                            "crypto/conf/conf_api.o",
                            "crypto/conf/conf_def.o",
                            "crypto/conf/conf_err.o",
                            "crypto/conf/conf_lib.o",
                            "crypto/conf/conf_mall.o",
                            "crypto/conf/conf_mod.o",
                            "crypto/conf/conf_sap.o",
                            "crypto/conf/conf_ssl.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/des" =>
                {
                    "deps" =>
                        [
                            "crypto/des/cbc_cksm.o",
                            "crypto/des/cbc_enc.o",
                            "crypto/des/cfb64ede.o",
                            "crypto/des/cfb64enc.o",
                            "crypto/des/cfb_enc.o",
                            "crypto/des/des_enc.o",
                            "crypto/des/ecb3_enc.o",
                            "crypto/des/ecb_enc.o",
                            "crypto/des/fcrypt.o",
                            "crypto/des/fcrypt_b.o",
                            "crypto/des/ofb64ede.o",
                            "crypto/des/ofb64enc.o",
                            "crypto/des/ofb_enc.o",
                            "crypto/des/pcbc_enc.o",
                            "crypto/des/qud_cksm.o",
                            "crypto/des/rand_key.o",
                            "crypto/des/set_key.o",
                            "crypto/des/str2key.o",
                            "crypto/des/xcbc_enc.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/dh" =>
                {
                    "deps" =>
                        [
                            "crypto/dh/dh_ameth.o",
                            "crypto/dh/dh_asn1.o",
                            "crypto/dh/dh_check.o",
                            "crypto/dh/dh_depr.o",
                            "crypto/dh/dh_err.o",
                            "crypto/dh/dh_gen.o",
                            "crypto/dh/dh_kdf.o",
                            "crypto/dh/dh_key.o",
                            "crypto/dh/dh_lib.o",
                            "crypto/dh/dh_meth.o",
                            "crypto/dh/dh_pmeth.o",
                            "crypto/dh/dh_prn.o",
                            "crypto/dh/dh_rfc5114.o",
                            "crypto/dh/dh_rfc7919.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/dso" =>
                {
                    "deps" =>
                        [
                            "crypto/dso/dso_dl.o",
                            "crypto/dso/dso_dlfcn.o",
                            "crypto/dso/dso_err.o",
                            "crypto/dso/dso_lib.o",
                            "crypto/dso/dso_openssl.o",
                            "crypto/dso/dso_vms.o",
                            "crypto/dso/dso_win32.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/ec" =>
                {
                    "deps" =>
                        [
                            "crypto/ec/curve25519.o",
                            "crypto/ec/ec2_oct.o",
                            "crypto/ec/ec2_smpl.o",
                            "crypto/ec/ec_ameth.o",
                            "crypto/ec/ec_asn1.o",
                            "crypto/ec/ec_check.o",
                            "crypto/ec/ec_curve.o",
                            "crypto/ec/ec_cvt.o",
                            "crypto/ec/ec_err.o",
                            "crypto/ec/ec_key.o",
                            "crypto/ec/ec_kmeth.o",
                            "crypto/ec/ec_lib.o",
                            "crypto/ec/ec_mult.o",
                            "crypto/ec/ec_oct.o",
                            "crypto/ec/ec_pmeth.o",
                            "crypto/ec/ec_print.o",
                            "crypto/ec/ecdh_kdf.o",
                            "crypto/ec/ecdh_ossl.o",
                            "crypto/ec/ecdsa_ossl.o",
                            "crypto/ec/ecdsa_sign.o",
                            "crypto/ec/ecdsa_vrf.o",
                            "crypto/ec/eck_prn.o",
                            "crypto/ec/ecp_mont.o",
                            "crypto/ec/ecp_nist.o",
                            "crypto/ec/ecp_nistp224.o",
                            "crypto/ec/ecp_nistp256.o",
                            "crypto/ec/ecp_nistp521.o",
                            "crypto/ec/ecp_nistputil.o",
                            "crypto/ec/ecp_oct.o",
                            "crypto/ec/ecp_smpl.o",
                            "crypto/ec/ecx_meth.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/ec/curve448" =>
                {
                    "deps" =>
                        [
                            "crypto/ec/curve448/curve448.o",
                            "crypto/ec/curve448/curve448_tables.o",
                            "crypto/ec/curve448/eddsa.o",
                            "crypto/ec/curve448/f_generic.o",
                            "crypto/ec/curve448/scalar.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/ec/curve448/arch_32" =>
                {
                    "deps" =>
                        [
                            "crypto/ec/curve448/arch_32/f_impl.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/err" =>
                {
                    "deps" =>
                        [
                            "crypto/err/err.o",
                            "crypto/err/err_all.o",
                            "crypto/err/err_prn.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/evp" =>
                {
                    "deps" =>
                        [
                            "crypto/evp/bio_b64.o",
                            "crypto/evp/bio_enc.o",
                            "crypto/evp/bio_md.o",
                            "crypto/evp/bio_ok.o",
                            "crypto/evp/c_allc.o",
                            "crypto/evp/c_alld.o",
                            "crypto/evp/cmeth_lib.o",
                            "crypto/evp/digest.o",
                            "crypto/evp/e_aes.o",
                            "crypto/evp/e_aes_cbc_hmac_sha1.o",
                            "crypto/evp/e_aes_cbc_hmac_sha256.o",
                            "crypto/evp/e_aria.o",
                            "crypto/evp/e_bf.o",
                            "crypto/evp/e_camellia.o",
                            "crypto/evp/e_cast.o",
                            "crypto/evp/e_chacha20_poly1305.o",
                            "crypto/evp/e_des.o",
                            "crypto/evp/e_des3.o",
                            "crypto/evp/e_idea.o",
                            "crypto/evp/e_null.o",
                            "crypto/evp/e_old.o",
                            "crypto/evp/e_rc2.o",
                            "crypto/evp/e_rc4.o",
                            "crypto/evp/e_rc4_hmac_md5.o",
                            "crypto/evp/e_rc5.o",
                            "crypto/evp/e_seed.o",
                            "crypto/evp/e_sm4.o",
                            "crypto/evp/e_xcbc_d.o",
                            "crypto/evp/encode.o",
                            "crypto/evp/evp_cnf.o",
                            "crypto/evp/evp_enc.o",
                            "crypto/evp/evp_err.o",
                            "crypto/evp/evp_key.o",
                            "crypto/evp/evp_lib.o",
                            "crypto/evp/evp_pbe.o",
                            "crypto/evp/evp_pkey.o",
                            "crypto/evp/m_md2.o",
                            "crypto/evp/m_md4.o",
                            "crypto/evp/m_md5.o",
                            "crypto/evp/m_md5_sha1.o",
                            "crypto/evp/m_mdc2.o",
                            "crypto/evp/m_null.o",
                            "crypto/evp/m_ripemd.o",
                            "crypto/evp/m_sha1.o",
                            "crypto/evp/m_sha3.o",
                            "crypto/evp/m_sigver.o",
                            "crypto/evp/m_wp.o",
                            "crypto/evp/names.o",
                            "crypto/evp/p5_crpt.o",
                            "crypto/evp/p5_crpt2.o",
                            "crypto/evp/p_dec.o",
                            "crypto/evp/p_enc.o",
                            "crypto/evp/p_lib.o",
                            "crypto/evp/p_open.o",
                            "crypto/evp/p_seal.o",
                            "crypto/evp/p_sign.o",
                            "crypto/evp/p_verify.o",
                            "crypto/evp/pbe_scrypt.o",
                            "crypto/evp/pmeth_fn.o",
                            "crypto/evp/pmeth_gn.o",
                            "crypto/evp/pmeth_lib.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/hmac" =>
                {
                    "deps" =>
                        [
                            "crypto/hmac/hm_ameth.o",
                            "crypto/hmac/hm_pmeth.o",
                            "crypto/hmac/hmac.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/kdf" =>
                {
                    "deps" =>
                        [
                            "crypto/kdf/hkdf.o",
                            "crypto/kdf/kdf_err.o",
                            "crypto/kdf/scrypt.o",
                            "crypto/kdf/tls1_prf.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/lhash" =>
                {
                    "deps" =>
                        [
                            "crypto/lhash/lh_stats.o",
                            "crypto/lhash/lhash.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/md5" =>
                {
                    "deps" =>
                        [
                            "crypto/md5/md5_dgst.o",
                            "crypto/md5/md5_one.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/modes" =>
                {
                    "deps" =>
                        [
                            "crypto/modes/cbc128.o",
                            "crypto/modes/ccm128.o",
                            "crypto/modes/cfb128.o",
                            "crypto/modes/ctr128.o",
                            "crypto/modes/cts128.o",
                            "crypto/modes/gcm128.o",
                            "crypto/modes/ocb128.o",
                            "crypto/modes/ofb128.o",
                            "crypto/modes/wrap128.o",
                            "crypto/modes/xts128.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/objects" =>
                {
                    "deps" =>
                        [
                            "crypto/objects/o_names.o",
                            "crypto/objects/obj_dat.o",
                            "crypto/objects/obj_err.o",
                            "crypto/objects/obj_lib.o",
                            "crypto/objects/obj_xref.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/pem" =>
                {
                    "deps" =>
                        [
                            "crypto/pem/pem_all.o",
                            "crypto/pem/pem_err.o",
                            "crypto/pem/pem_info.o",
                            "crypto/pem/pem_lib.o",
                            "crypto/pem/pem_oth.o",
                            "crypto/pem/pem_pk8.o",
                            "crypto/pem/pem_pkey.o",
                            "crypto/pem/pem_sign.o",
                            "crypto/pem/pem_x509.o",
                            "crypto/pem/pem_xaux.o",
                            "crypto/pem/pvkfmt.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/pkcs12" =>
                {
                    "deps" =>
                        [
                            "crypto/pkcs12/p12_add.o",
                            "crypto/pkcs12/p12_asn.o",
                            "crypto/pkcs12/p12_attr.o",
                            "crypto/pkcs12/p12_crpt.o",
                            "crypto/pkcs12/p12_crt.o",
                            "crypto/pkcs12/p12_decr.o",
                            "crypto/pkcs12/p12_init.o",
                            "crypto/pkcs12/p12_key.o",
                            "crypto/pkcs12/p12_kiss.o",
                            "crypto/pkcs12/p12_mutl.o",
                            "crypto/pkcs12/p12_npas.o",
                            "crypto/pkcs12/p12_p8d.o",
                            "crypto/pkcs12/p12_p8e.o",
                            "crypto/pkcs12/p12_sbag.o",
                            "crypto/pkcs12/p12_utl.o",
                            "crypto/pkcs12/pk12err.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/pkcs7" =>
                {
                    "deps" =>
                        [
                            "crypto/pkcs7/bio_pk7.o",
                            "crypto/pkcs7/pk7_asn1.o",
                            "crypto/pkcs7/pk7_attr.o",
                            "crypto/pkcs7/pk7_doit.o",
                            "crypto/pkcs7/pk7_lib.o",
                            "crypto/pkcs7/pk7_mime.o",
                            "crypto/pkcs7/pk7_smime.o",
                            "crypto/pkcs7/pkcs7err.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/rand" =>
                {
                    "deps" =>
                        [
                            "crypto/rand/drbg_ctr.o",
                            "crypto/rand/drbg_lib.o",
                            "crypto/rand/rand_egd.o",
                            "crypto/rand/rand_err.o",
                            "crypto/rand/rand_lib.o",
                            "crypto/rand/rand_unix.o",
                            "crypto/rand/rand_vms.o",
                            "crypto/rand/rand_win.o",
                            "crypto/rand/randfile.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/rc4" =>
                {
                    "deps" =>
                        [
                            "crypto/rc4/rc4_enc.o",
                            "crypto/rc4/rc4_skey.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/rsa" =>
                {
                    "deps" =>
                        [
                            "crypto/rsa/rsa_ameth.o",
                            "crypto/rsa/rsa_asn1.o",
                            "crypto/rsa/rsa_chk.o",
                            "crypto/rsa/rsa_crpt.o",
                            "crypto/rsa/rsa_depr.o",
                            "crypto/rsa/rsa_err.o",
                            "crypto/rsa/rsa_gen.o",
                            "crypto/rsa/rsa_lib.o",
                            "crypto/rsa/rsa_meth.o",
                            "crypto/rsa/rsa_mp.o",
                            "crypto/rsa/rsa_none.o",
                            "crypto/rsa/rsa_oaep.o",
                            "crypto/rsa/rsa_ossl.o",
                            "crypto/rsa/rsa_pk1.o",
                            "crypto/rsa/rsa_pmeth.o",
                            "crypto/rsa/rsa_prn.o",
                            "crypto/rsa/rsa_pss.o",
                            "crypto/rsa/rsa_saos.o",
                            "crypto/rsa/rsa_sign.o",
                            "crypto/rsa/rsa_ssl.o",
                            "crypto/rsa/rsa_x931.o",
                            "crypto/rsa/rsa_x931g.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/sha" =>
                {
                    "deps" =>
                        [
                            "crypto/sha/keccak1600.o",
                            "crypto/sha/sha1_one.o",
                            "crypto/sha/sha1dgst.o",
                            "crypto/sha/sha256.o",
                            "crypto/sha/sha512.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/siphash" =>
                {
                    "deps" =>
                        [
                            "crypto/siphash/siphash.o",
                            "crypto/siphash/siphash_ameth.o",
                            "crypto/siphash/siphash_pmeth.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/sm2" =>
                {
                    "deps" =>
                        [
                            "crypto/sm2/sm2_crypt.o",
                            "crypto/sm2/sm2_err.o",
                            "crypto/sm2/sm2_pmeth.o",
                            "crypto/sm2/sm2_sign.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/sm3" =>
                {
                    "deps" =>
                        [
                            "crypto/sm3/m_sm3.o",
                            "crypto/sm3/sm3.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/sm4" =>
                {
                    "deps" =>
                        [
                            "crypto/sm4/sm4.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/stack" =>
                {
                    "deps" =>
                        [
                            "crypto/stack/stack.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/store" =>
                {
                    "deps" =>
                        [
                            "crypto/store/loader_file.o",
                            "crypto/store/store_err.o",
                            "crypto/store/store_init.o",
                            "crypto/store/store_lib.o",
                            "crypto/store/store_register.o",
                            "crypto/store/store_strings.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/txt_db" =>
                {
                    "deps" =>
                        [
                            "crypto/txt_db/txt_db.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/ui" =>
                {
                    "deps" =>
                        [
                            "crypto/ui/ui_err.o",
                            "crypto/ui/ui_lib.o",
                            "crypto/ui/ui_null.o",
                            "crypto/ui/ui_openssl.o",
                            "crypto/ui/ui_util.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/x509" =>
                {
                    "deps" =>
                        [
                            "crypto/x509/by_dir.o",
                            "crypto/x509/by_file.o",
                            "crypto/x509/t_crl.o",
                            "crypto/x509/t_req.o",
                            "crypto/x509/t_x509.o",
                            "crypto/x509/x509_att.o",
                            "crypto/x509/x509_cmp.o",
                            "crypto/x509/x509_d2.o",
                            "crypto/x509/x509_def.o",
                            "crypto/x509/x509_err.o",
                            "crypto/x509/x509_ext.o",
                            "crypto/x509/x509_lu.o",
                            "crypto/x509/x509_meth.o",
                            "crypto/x509/x509_obj.o",
                            "crypto/x509/x509_r2x.o",
                            "crypto/x509/x509_req.o",
                            "crypto/x509/x509_set.o",
                            "crypto/x509/x509_trs.o",
                            "crypto/x509/x509_txt.o",
                            "crypto/x509/x509_v3.o",
                            "crypto/x509/x509_vfy.o",
                            "crypto/x509/x509_vpm.o",
                            "crypto/x509/x509cset.o",
                            "crypto/x509/x509name.o",
                            "crypto/x509/x509rset.o",
                            "crypto/x509/x509spki.o",
                            "crypto/x509/x509type.o",
                            "crypto/x509/x_all.o",
                            "crypto/x509/x_attrib.o",
                            "crypto/x509/x_crl.o",
                            "crypto/x509/x_exten.o",
                            "crypto/x509/x_name.o",
                            "crypto/x509/x_pubkey.o",
                            "crypto/x509/x_req.o",
                            "crypto/x509/x_x509.o",
                            "crypto/x509/x_x509a.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "crypto/x509v3" =>
                {
                    "deps" =>
                        [
                            "crypto/x509v3/pcy_cache.o",
                            "crypto/x509v3/pcy_data.o",
                            "crypto/x509v3/pcy_lib.o",
                            "crypto/x509v3/pcy_map.o",
                            "crypto/x509v3/pcy_node.o",
                            "crypto/x509v3/pcy_tree.o",
                            "crypto/x509v3/v3_addr.o",
                            "crypto/x509v3/v3_admis.o",
                            "crypto/x509v3/v3_akey.o",
                            "crypto/x509v3/v3_akeya.o",
                            "crypto/x509v3/v3_alt.o",
                            "crypto/x509v3/v3_asid.o",
                            "crypto/x509v3/v3_bcons.o",
                            "crypto/x509v3/v3_bitst.o",
                            "crypto/x509v3/v3_conf.o",
                            "crypto/x509v3/v3_cpols.o",
                            "crypto/x509v3/v3_crld.o",
                            "crypto/x509v3/v3_enum.o",
                            "crypto/x509v3/v3_extku.o",
                            "crypto/x509v3/v3_genn.o",
                            "crypto/x509v3/v3_ia5.o",
                            "crypto/x509v3/v3_info.o",
                            "crypto/x509v3/v3_int.o",
                            "crypto/x509v3/v3_lib.o",
                            "crypto/x509v3/v3_ncons.o",
                            "crypto/x509v3/v3_pci.o",
                            "crypto/x509v3/v3_pcia.o",
                            "crypto/x509v3/v3_pcons.o",
                            "crypto/x509v3/v3_pku.o",
                            "crypto/x509v3/v3_pmaps.o",
                            "crypto/x509v3/v3_prn.o",
                            "crypto/x509v3/v3_purp.o",
                            "crypto/x509v3/v3_skey.o",
                            "crypto/x509v3/v3_sxnet.o",
                            "crypto/x509v3/v3_tlsf.o",
                            "crypto/x509v3/v3_utl.o",
                            "crypto/x509v3/v3err.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libcrypto",
                                ],
                        },
                },
            "ssl" =>
                {
                    "deps" =>
                        [
                            "ssl/bio_ssl.o",
                            "ssl/d1_lib.o",
                            "ssl/d1_msg.o",
                            "ssl/d1_srtp.o",
                            "ssl/methods.o",
                            "ssl/packet.o",
                            "ssl/pqueue.o",
                            "ssl/s3_cbc.o",
                            "ssl/s3_enc.o",
                            "ssl/s3_lib.o",
                            "ssl/s3_msg.o",
                            "ssl/ssl_asn1.o",
                            "ssl/ssl_cert.o",
                            "ssl/ssl_ciph.o",
                            "ssl/ssl_conf.o",
                            "ssl/ssl_err.o",
                            "ssl/ssl_init.o",
                            "ssl/ssl_lib.o",
                            "ssl/ssl_mcnf.o",
                            "ssl/ssl_rsa.o",
                            "ssl/ssl_sess.o",
                            "ssl/ssl_stat.o",
                            "ssl/ssl_txt.o",
                            "ssl/ssl_utst.o",
                            "ssl/t1_enc.o",
                            "ssl/t1_lib.o",
                            "ssl/t1_trce.o",
                            "ssl/tls13_enc.o",
                            "ssl/tls_srp.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libssl",
                                ],
                        },
                },
            "ssl/record" =>
                {
                    "deps" =>
                        [
                            "ssl/record/dtls1_bitmap.o",
                            "ssl/record/rec_layer_d1.o",
                            "ssl/record/rec_layer_s3.o",
                            "ssl/record/ssl3_buffer.o",
                            "ssl/record/ssl3_record.o",
                            "ssl/record/ssl3_record_tls13.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libssl",
                                ],
                        },
                },
            "ssl/statem" =>
                {
                    "deps" =>
                        [
                            "ssl/statem/extensions.o",
                            "ssl/statem/extensions_clnt.o",
                            "ssl/statem/extensions_cust.o",
                            "ssl/statem/extensions_srvr.o",
                            "ssl/statem/statem.o",
                            "ssl/statem/statem_clnt.o",
                            "ssl/statem/statem_dtls.o",
                            "ssl/statem/statem_lib.o",
                            "ssl/statem/statem_srvr.o",
                        ],
                    "products" =>
                        {
                            "lib" =>
                                [
                                    "libssl",
                                ],
                        },
                },
        },
    "engines" =>
        [
        ],
    "extra" =>
        [
            "crypto/alphacpuid.pl",
            "crypto/arm64cpuid.pl",
            "crypto/armv4cpuid.pl",
            "crypto/ia64cpuid.S",
            "crypto/pariscid.pl",
            "crypto/ppccpuid.pl",
            "crypto/x86_64cpuid.pl",
            "crypto/x86cpuid.pl",
            "ms/applink.c",
            "ms/uplink-x86.pl",
            "ms/uplink.c",
        ],
    "generate" =>
        {
            "crypto/aes/aes-586.s" =>
                [
                    "../openssl/crypto/aes/asm/aes-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/aes/aes-armv4.S" =>
                [
                    "../openssl/crypto/aes/asm/aes-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-ia64.s" =>
                [
                    "../openssl/crypto/aes/asm/aes-ia64.S",
                ],
            "crypto/aes/aes-mips.S" =>
                [
                    "../openssl/crypto/aes/asm/aes-mips.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-parisc.s" =>
                [
                    "../openssl/crypto/aes/asm/aes-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-ppc.s" =>
                [
                    "../openssl/crypto/aes/asm/aes-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-s390x.S" =>
                [
                    "../openssl/crypto/aes/asm/aes-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-sparcv9.S" =>
                [
                    "../openssl/crypto/aes/asm/aes-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aes-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/aes-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesfx-sparcv9.S" =>
                [
                    "../openssl/crypto/aes/asm/aesfx-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesni-mb-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/aesni-mb-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesni-sha1-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/aesni-sha1-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesni-sha256-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/aesni-sha256-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesni-x86.s" =>
                [
                    "../openssl/crypto/aes/asm/aesni-x86.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/aes/aesni-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/aesni-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesp8-ppc.s" =>
                [
                    "../openssl/crypto/aes/asm/aesp8-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aest4-sparcv9.S" =>
                [
                    "../openssl/crypto/aes/asm/aest4-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/aesv8-armx.S" =>
                [
                    "../openssl/crypto/aes/asm/aesv8-armx.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/bsaes-armv7.S" =>
                [
                    "../openssl/crypto/aes/asm/bsaes-armv7.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/bsaes-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/bsaes-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/vpaes-armv8.S" =>
                [
                    "../openssl/crypto/aes/asm/vpaes-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/vpaes-ppc.s" =>
                [
                    "../openssl/crypto/aes/asm/vpaes-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/aes/vpaes-x86.s" =>
                [
                    "../openssl/crypto/aes/asm/vpaes-x86.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/aes/vpaes-x86_64.s" =>
                [
                    "../openssl/crypto/aes/asm/vpaes-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/alphacpuid.s" =>
                [
                    "../openssl/crypto/alphacpuid.pl",
                ],
            "crypto/arm64cpuid.S" =>
                [
                    "../openssl/crypto/arm64cpuid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/armv4cpuid.S" =>
                [
                    "../openssl/crypto/armv4cpuid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/alpha-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/alpha-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/armv4-gf2m.S" =>
                [
                    "../openssl/crypto/bn/asm/armv4-gf2m.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/armv4-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/armv4-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/armv8-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/armv8-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/bn-586.s" =>
                [
                    "../openssl/crypto/bn/asm/bn-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/bn/bn-ia64.s" =>
                [
                    "../openssl/crypto/bn/asm/ia64.S",
                ],
            "crypto/bn/bn-mips.S" =>
                [
                    "../openssl/crypto/bn/asm/mips.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/bn-ppc.s" =>
                [
                    "../openssl/crypto/bn/asm/ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/co-586.s" =>
                [
                    "../openssl/crypto/bn/asm/co-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/bn/ia64-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/ia64-mont.pl",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/bn/mips-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/mips-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/parisc-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/parisc-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/ppc-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/ppc-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/ppc64-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/ppc64-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/rsaz-avx2.s" =>
                [
                    "../openssl/crypto/bn/asm/rsaz-avx2.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/rsaz-x86_64.s" =>
                [
                    "../openssl/crypto/bn/asm/rsaz-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/s390x-gf2m.s" =>
                [
                    "../openssl/crypto/bn/asm/s390x-gf2m.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/s390x-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/s390x-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/sparct4-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/sparct4-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/sparcv9-gf2m.S" =>
                [
                    "../openssl/crypto/bn/asm/sparcv9-gf2m.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/sparcv9-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/sparcv9-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/sparcv9a-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/sparcv9a-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/vis3-mont.S" =>
                [
                    "../openssl/crypto/bn/asm/vis3-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/x86-gf2m.s" =>
                [
                    "../openssl/crypto/bn/asm/x86-gf2m.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/bn/x86-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/x86-mont.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/bn/x86_64-gf2m.s" =>
                [
                    "../openssl/crypto/bn/asm/x86_64-gf2m.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/x86_64-mont.s" =>
                [
                    "../openssl/crypto/bn/asm/x86_64-mont.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/bn/x86_64-mont5.s" =>
                [
                    "../openssl/crypto/bn/asm/x86_64-mont5.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/buildinf.h" =>
                [
                    "../openssl/util/mkbuildinf.pl",
                    "\"\$(CC)",
                    "\$(LIB_CFLAGS)",
                    "\$(CPPFLAGS_Q)\"",
                    "\"\$(PLATFORM)\"",
                ],
            "crypto/camellia/cmll-x86.s" =>
                [
                    "../openssl/crypto/camellia/asm/cmll-x86.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/camellia/cmll-x86_64.s" =>
                [
                    "../openssl/crypto/camellia/asm/cmll-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/camellia/cmllt4-sparcv9.S" =>
                [
                    "../openssl/crypto/camellia/asm/cmllt4-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/des/crypt586.s" =>
                [
                    "../openssl/crypto/des/asm/crypt586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/des/des-586.s" =>
                [
                    "../openssl/crypto/des/asm/des-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/des/des_enc-sparc.S" =>
                [
                    "../openssl/crypto/des/asm/des_enc.m4",
                ],
            "crypto/des/dest4-sparcv9.S" =>
                [
                    "../openssl/crypto/des/asm/dest4-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-armv4.S" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-armv8.S" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-avx2.s" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-avx2.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-ppc64.s" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-ppc64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-sparcv9.S" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/ecp_nistz256-x86.s" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-x86.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/ec/ecp_nistz256-x86_64.s" =>
                [
                    "../openssl/crypto/ec/asm/ecp_nistz256-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/x25519-ppc64.s" =>
                [
                    "../openssl/crypto/ec/asm/x25519-ppc64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ec/x25519-x86_64.s" =>
                [
                    "../openssl/crypto/ec/asm/x25519-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ia64cpuid.s" =>
                [
                    "../openssl/crypto/ia64cpuid.S",
                ],
            "crypto/md5/md5-586.s" =>
                [
                    "../openssl/crypto/md5/asm/md5-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/md5/md5-sparcv9.S" =>
                [
                    "../openssl/crypto/md5/asm/md5-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/md5/md5-x86_64.s" =>
                [
                    "../openssl/crypto/md5/asm/md5-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/aesni-gcm-x86_64.s" =>
                [
                    "../openssl/crypto/modes/asm/aesni-gcm-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-alpha.S" =>
                [
                    "../openssl/crypto/modes/asm/ghash-alpha.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-armv4.S" =>
                [
                    "../openssl/crypto/modes/asm/ghash-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-ia64.s" =>
                [
                    "../openssl/crypto/modes/asm/ghash-ia64.pl",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/modes/ghash-parisc.s" =>
                [
                    "../openssl/crypto/modes/asm/ghash-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-s390x.S" =>
                [
                    "../openssl/crypto/modes/asm/ghash-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-sparcv9.S" =>
                [
                    "../openssl/crypto/modes/asm/ghash-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghash-x86.s" =>
                [
                    "../openssl/crypto/modes/asm/ghash-x86.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/modes/ghash-x86_64.s" =>
                [
                    "../openssl/crypto/modes/asm/ghash-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghashp8-ppc.s" =>
                [
                    "../openssl/crypto/modes/asm/ghashp8-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/modes/ghashv8-armx.S" =>
                [
                    "../openssl/crypto/modes/asm/ghashv8-armx.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/pariscid.s" =>
                [
                    "../openssl/crypto/pariscid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/ppccpuid.s" =>
                [
                    "../openssl/crypto/ppccpuid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/rc4/rc4-586.s" =>
                [
                    "../openssl/crypto/rc4/asm/rc4-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/rc4/rc4-md5-x86_64.s" =>
                [
                    "../openssl/crypto/rc4/asm/rc4-md5-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/rc4/rc4-parisc.s" =>
                [
                    "../openssl/crypto/rc4/asm/rc4-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/rc4/rc4-s390x.s" =>
                [
                    "../openssl/crypto/rc4/asm/rc4-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/rc4/rc4-x86_64.s" =>
                [
                    "../openssl/crypto/rc4/asm/rc4-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/s390xcpuid.S" =>
                [
                    "../openssl/crypto/s390xcpuid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/keccak1600-armv4.S" =>
                [
                    "../openssl/crypto/sha/asm/keccak1600-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/keccak1600-armv8.S" =>
                [
                    "../openssl/crypto/sha/asm/keccak1600-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/keccak1600-ppc64.s" =>
                [
                    "../openssl/crypto/sha/asm/keccak1600-ppc64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/keccak1600-s390x.S" =>
                [
                    "../openssl/crypto/sha/asm/keccak1600-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/keccak1600-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/keccak1600-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-586.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/sha/sha1-alpha.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-alpha.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-armv4-large.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-armv4-large.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-armv8.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-ia64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-ia64.pl",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/sha/sha1-mb-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-mb-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-mips.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-mips.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-parisc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-ppc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-s390x.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-sparcv9.S" =>
                [
                    "../openssl/crypto/sha/asm/sha1-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha1-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha1-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-586.s" =>
                [
                    "../openssl/crypto/sha/asm/sha256-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/sha/sha256-armv4.S" =>
                [
                    "../openssl/crypto/sha/asm/sha256-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-armv8.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-ia64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-ia64.pl",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/sha/sha256-mb-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha256-mb-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-mips.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-mips.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-parisc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-ppc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-s390x.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-sparcv9.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha256p8-ppc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512p8-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-586.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-586.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "crypto/sha/sha512-armv4.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-armv4.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-armv8.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-armv8.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-ia64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-ia64.pl",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                ],
            "crypto/sha/sha512-mips.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-mips.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-parisc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-parisc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-ppc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-s390x.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-s390x.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-sparcv9.S" =>
                [
                    "../openssl/crypto/sha/asm/sha512-sparcv9.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512-x86_64.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/sha/sha512p8-ppc.s" =>
                [
                    "../openssl/crypto/sha/asm/sha512p8-ppc.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/uplink-ia64.s" =>
                [
                    "../openssl/ms/uplink-ia64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/uplink-x86.s" =>
                [
                    "../openssl/ms/uplink-x86.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/uplink-x86_64.s" =>
                [
                    "../openssl/ms/uplink-x86_64.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/x86_64cpuid.s" =>
                [
                    "../openssl/crypto/x86_64cpuid.pl",
                    "\$(PERLASM_SCHEME)",
                ],
            "crypto/x86cpuid.s" =>
                [
                    "../openssl/crypto/x86cpuid.pl",
                    "\$(PERLASM_SCHEME)",
                    "\$(LIB_CFLAGS)",
                    "\$(LIB_CPPFLAGS)",
                    "\$(PROCESSOR)",
                ],
            "include/crypto/bn_conf.h" =>
                [
                    "../openssl/include/crypto/bn_conf.h.in",
                ],
            "include/crypto/dso_conf.h" =>
                [
                    "../openssl/include/crypto/dso_conf.h.in",
                ],
            "include/openssl/opensslconf.h" =>
                [
                    "../openssl/include/openssl/opensslconf.h.in",
                ],
        },
    "includes" =>
        {
            "crypto/aes/aes-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aes-mips.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aes-s390x.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aes-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aes_cbc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_cfb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_core.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_ecb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_ige.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_misc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_ofb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aes_wrap.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/aes/aesfx-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aest4-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/aesv8-armx.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/aes/bsaes-armv7.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/arm64cpuid.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/armv4cpuid.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/asn1/a_bitstr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_d2i_fp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_digest.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_dup.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_gentm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_i2d_fp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_int.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_mbstr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_object.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_octet.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_print.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_strex.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_strnid.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_time.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_type.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_utctm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_utf8.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/a_verify.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/ameth_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn1_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn1_gen.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn1_item_list.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn1_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn1_par.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn_mime.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn_moid.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn_mstbl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/asn_pack.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/bio_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/bio_ndef.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/d2i_pr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/d2i_pu.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/evp_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/f_int.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/f_string.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/i2d_pr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/i2d_pu.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/n_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/nsseq.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/p5_pbe.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/p5_pbev2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/p5_scrypt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/p8_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/t_bitst.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/t_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/t_spki.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_dec.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_fre.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_new.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_scn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_typ.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/tasn_utl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_algor.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_bignum.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_info.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_int64.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_long.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_sig.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_spki.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/asn1/x_val.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/arch/async_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/arch/async_posix.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/arch/async_win.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/async.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/async_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/async/async_wait.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/b_addr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/b_dump.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/b_print.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/b_sock.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/b_sock2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bf_buff.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bf_lbuf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bf_nbio.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bf_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bio_cb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bio_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bio_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bio_meth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_acpt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_bio.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_conn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_dgram.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_fd.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_file.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_log.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_mem.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bio/bss_sock.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/armv4-gf2m.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/armv4-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/bn-mips.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/bn_add.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_asm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_blind.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_const.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_ctx.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_depr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_dh.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_div.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_exp.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                ],
            "crypto/bn/bn_exp2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_gcd.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_gf2m.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_intern.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_kron.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_mod.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_mont.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_mpi.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_mul.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_nist.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_prime.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_print.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_rand.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_recp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_shift.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_sqr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_sqrt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_srp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_word.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/bn_x931p.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/bn/mips-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/sparct4-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/sparcv9-gf2m.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/sparcv9-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/sparcv9a-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/bn/vis3-mont.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/buffer/buf_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/buffer/buffer.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/buildinf.h" =>
                [
                    ".",
                ],
            "crypto/camellia/camellia.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_cbc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_cfb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_ctr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_ecb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_misc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmll_ofb.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/camellia/cmllt4-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/cmac/cm_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/cmac/cm_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/cmac/cmac.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_api.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_def.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_mall.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_mod.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_sap.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/conf/conf_ssl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/cpt_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/cryptlib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ctype.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/cversion.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/cbc_cksm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/cbc_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/cfb64ede.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/cfb64enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/cfb_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/des_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/dest4-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/des/ecb3_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/ecb_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/fcrypt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/fcrypt_b.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/ofb64ede.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/ofb64enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/ofb_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/pcbc_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/qud_cksm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/rand_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/set_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/str2key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/des/xcbc_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_check.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_depr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_gen.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_kdf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_meth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_rfc5114.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dh/dh_rfc7919.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_dl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_dlfcn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_openssl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_vms.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/dso/dso_win32.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ebcdic.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/curve25519.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/curve448/arch_32/f_impl.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/curve448/curve448.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/curve448/curve448_tables.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/curve448/eddsa.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/curve448/f_generic.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/curve448/scalar.o" =>
                [
                    ".",
                    "include",
                    "crypto/ec/curve448/arch_32",
                    "crypto/ec/curve448",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/ec/curve448/arch_32",
                    "../openssl/crypto/ec/curve448",
                ],
            "crypto/ec/ec2_oct.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec2_smpl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_check.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_curve.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_cvt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_kmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_mult.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_oct.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ec_print.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecdh_kdf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecdh_ossl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecdsa_ossl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecdsa_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecdsa_vrf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/eck_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_mont.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nist.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nistp224.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nistp256.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nistp521.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nistputil.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_nistz256-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/ec/ecp_nistz256-armv8.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/ec/ecp_nistz256-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/ec/ecp_oct.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecp_smpl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ec/ecx_meth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/err/err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/err/err_all.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/err/err_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/bio_b64.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/bio_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/bio_md.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/bio_ok.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/c_allc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/c_alld.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/cmeth_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/digest.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_aes.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_aes_cbc_hmac_sha1.o" =>
                [
                    ".",
                    "include",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_aes_cbc_hmac_sha256.o" =>
                [
                    ".",
                    "include",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_aria.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_bf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_camellia.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_cast.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_chacha20_poly1305.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_des.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                ],
            "crypto/evp/e_des3.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                ],
            "crypto/evp/e_idea.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_old.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_rc2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_rc4.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_rc4_hmac_md5.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_rc5.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_seed.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/e_sm4.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                    "../openssl/crypto/modes",
                ],
            "crypto/evp/e_xcbc_d.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/encode.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_cnf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_pbe.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/evp_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_md2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_md4.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_md5.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_md5_sha1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_mdc2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_ripemd.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_sha1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_sha3.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                ],
            "crypto/evp/m_sigver.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/m_wp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/names.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p5_crpt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p5_crpt2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_dec.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_open.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_seal.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/p_verify.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/pbe_scrypt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/pmeth_fn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/pmeth_gn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/evp/pmeth_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ex_data.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/getenv.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/hmac/hm_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/hmac/hm_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/hmac/hmac.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/init.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/kdf/hkdf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/kdf/kdf_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/kdf/scrypt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/kdf/tls1_prf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/lhash/lh_stats.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/lhash/lhash.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/md5/md5-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/md5/md5_dgst.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/md5/md5_one.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/mem.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/mem_clr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/mem_dbg.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/mem_sec.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/cbc128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/ccm128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/cfb128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/ctr128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/cts128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/gcm128.o" =>
                [
                    ".",
                    "include",
                    "crypto",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto",
                ],
            "crypto/modes/ghash-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/modes/ghash-s390x.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/modes/ghash-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/modes/ghashv8-armx.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/modes/ocb128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/ofb128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/wrap128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/modes/xts128.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_dir.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_fips.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_fopen.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_init.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_str.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/o_time.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/objects/o_names.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/objects/obj_dat.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/objects/obj_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/objects/obj_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/objects/obj_xref.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_all.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_info.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_oth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_pk8.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_pkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_x509.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pem_xaux.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pem/pvkfmt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_add.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_asn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_attr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_crpt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_crt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_decr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_init.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_key.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_kiss.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_mutl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_npas.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_p8d.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_p8e.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_sbag.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/p12_utl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs12/pk12err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/bio_pk7.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_attr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_doit.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_mime.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pk7_smime.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/pkcs7/pkcs7err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/drbg_ctr.o" =>
                [
                    ".",
                    "include",
                    "crypto/modes",
                    "../openssl",
                    "../openssl/include",
                    "../openssl/crypto/modes",
                ],
            "crypto/rand/drbg_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_egd.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_unix.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_vms.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/rand_win.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rand/randfile.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rc4/rc4_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rc4/rc4_skey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_chk.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_crpt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_depr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_gen.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_meth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_mp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_none.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_oaep.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_ossl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_pk1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_pss.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_saos.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_ssl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_x931.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/rsa/rsa_x931g.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/s390xcpuid.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/keccak1600-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/keccak1600.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sha/sha1-armv4-large.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha1-armv8.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha1-mips.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha1-s390x.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha1-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha1_one.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sha/sha1dgst.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sha/sha256-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha256-armv8.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha256-mips.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha256-s390x.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha256-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha256.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sha/sha512-armv4.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha512-armv8.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha512-mips.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha512-s390x.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha512-sparcv9.o" =>
                [
                    "crypto",
                    "../openssl/crypto",
                ],
            "crypto/sha/sha512.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/siphash/siphash.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/siphash/siphash_ameth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/siphash/siphash_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm2/sm2_crypt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm2/sm2_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm2/sm2_pmeth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm2/sm2_sign.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm3/m_sm3.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm3/sm3.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/sm4/sm4.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/stack/stack.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/loader_file.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/store_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/store_init.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/store_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/store_register.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/store/store_strings.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/threads_none.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/threads_pthread.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/threads_win.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/txt_db/txt_db.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ui/ui_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ui/ui_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ui/ui_null.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ui/ui_openssl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/ui/ui_util.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/uid.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/by_dir.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/by_file.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/t_crl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/t_req.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/t_x509.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_att.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_cmp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_d2.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_def.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_ext.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_lu.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_meth.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_obj.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_r2x.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_req.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_set.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_trs.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_txt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_v3.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_vfy.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509_vpm.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509cset.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509name.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509rset.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509spki.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x509type.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_all.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_attrib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_crl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_exten.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_name.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_pubkey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_req.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_x509.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509/x_x509a.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_cache.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_data.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_map.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_node.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/pcy_tree.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_addr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_admis.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_akey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_akeya.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_alt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_asid.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_bcons.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_bitst.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_conf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_cpols.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_crld.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_enum.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_extku.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_genn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_ia5.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_info.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_int.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_ncons.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_pci.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_pcia.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_pcons.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_pku.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_pmaps.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_prn.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_purp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_skey.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_sxnet.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_tlsf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3_utl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "crypto/x509v3/v3err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "include/crypto/bn_conf.h" =>
                [
                    ".",
                ],
            "include/crypto/dso_conf.h" =>
                [
                    ".",
                ],
            "include/openssl/opensslconf.h" =>
                [
                    ".",
                ],
            "ssl/bio_ssl.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/d1_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/d1_msg.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/d1_srtp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/methods.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/packet.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/pqueue.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/dtls1_bitmap.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/rec_layer_d1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/rec_layer_s3.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/ssl3_buffer.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/ssl3_record.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/record/ssl3_record_tls13.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/s3_cbc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/s3_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/s3_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/s3_msg.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_asn1.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_cert.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_ciph.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_conf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_err.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_init.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_mcnf.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_rsa.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_sess.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_stat.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_txt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/ssl_utst.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/extensions.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/extensions_clnt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/extensions_cust.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/extensions_srvr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/statem.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/statem_clnt.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/statem_dtls.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/statem_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/statem/statem_srvr.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/t1_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/t1_lib.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/t1_trce.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/tls13_enc.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
            "ssl/tls_srp.o" =>
                [
                    ".",
                    "include",
                    "../openssl",
                    "../openssl/include",
                ],
        },
    "install" =>
        {
            "libraries" =>
                [
                    "libcrypto",
                    "libssl",
                ],
        },
    "ldadd" =>
        {
        },
    "libraries" =>
        [
            "libcrypto",
            "libssl",
        ],
    "overrides" =>
        [
        ],
    "programs" =>
        [
        ],
    "rawlines" =>
        [
            "##### SHA assembler implementations",
            "",
            "# GNU make \"catch all\"",
            "crypto/sha/sha1-%.S:	../openssl/crypto/sha/asm/sha1-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "crypto/sha/sha256-%.S:	../openssl/crypto/sha/asm/sha512-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "crypto/sha/sha512-%.S:	../openssl/crypto/sha/asm/sha512-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "##### AES assembler implementations",
            "",
            "# GNU make \"catch all\"",
            "crypto/aes/aes-%.S:	../openssl/crypto/aes/asm/aes-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "crypto/aes/bsaes-%.S:	../openssl/crypto/aes/asm/bsaes-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "",
            "# GNU make \"catch all\"",
            "crypto/rc4/rc4-%.s:	../openssl/crypto/rc4/asm/rc4-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "# GNU make \"catch all\"",
            "crypto/modes/ghash-%.S:	../openssl/crypto/modes/asm/ghash-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
            "crypto/ec/ecp_nistz256-%.S:	../openssl/crypto/ec/asm/ecp_nistz256-%.pl",
            "	CC=\"\$(CC)\" \$(PERL) \$< \$(PERLASM_SCHEME) \$\@",
        ],
    "rename" =>
        {
        },
    "scripts" =>
        [
            "util/shlib_wrap.sh",
        ],
    "shared_sources" =>
        {
        },
    "sources" =>
        {
            "crypto/aes/aes_cbc.o" =>
                [
                    "../openssl/crypto/aes/aes_cbc.c",
                ],
            "crypto/aes/aes_cfb.o" =>
                [
                    "../openssl/crypto/aes/aes_cfb.c",
                ],
            "crypto/aes/aes_core.o" =>
                [
                    "../openssl/crypto/aes/aes_core.c",
                ],
            "crypto/aes/aes_ecb.o" =>
                [
                    "../openssl/crypto/aes/aes_ecb.c",
                ],
            "crypto/aes/aes_ige.o" =>
                [
                    "../openssl/crypto/aes/aes_ige.c",
                ],
            "crypto/aes/aes_misc.o" =>
                [
                    "../openssl/crypto/aes/aes_misc.c",
                ],
            "crypto/aes/aes_ofb.o" =>
                [
                    "../openssl/crypto/aes/aes_ofb.c",
                ],
            "crypto/aes/aes_wrap.o" =>
                [
                    "../openssl/crypto/aes/aes_wrap.c",
                ],
            "crypto/asn1/a_bitstr.o" =>
                [
                    "../openssl/crypto/asn1/a_bitstr.c",
                ],
            "crypto/asn1/a_d2i_fp.o" =>
                [
                    "../openssl/crypto/asn1/a_d2i_fp.c",
                ],
            "crypto/asn1/a_digest.o" =>
                [
                    "../openssl/crypto/asn1/a_digest.c",
                ],
            "crypto/asn1/a_dup.o" =>
                [
                    "../openssl/crypto/asn1/a_dup.c",
                ],
            "crypto/asn1/a_gentm.o" =>
                [
                    "../openssl/crypto/asn1/a_gentm.c",
                ],
            "crypto/asn1/a_i2d_fp.o" =>
                [
                    "../openssl/crypto/asn1/a_i2d_fp.c",
                ],
            "crypto/asn1/a_int.o" =>
                [
                    "../openssl/crypto/asn1/a_int.c",
                ],
            "crypto/asn1/a_mbstr.o" =>
                [
                    "../openssl/crypto/asn1/a_mbstr.c",
                ],
            "crypto/asn1/a_object.o" =>
                [
                    "../openssl/crypto/asn1/a_object.c",
                ],
            "crypto/asn1/a_octet.o" =>
                [
                    "../openssl/crypto/asn1/a_octet.c",
                ],
            "crypto/asn1/a_print.o" =>
                [
                    "../openssl/crypto/asn1/a_print.c",
                ],
            "crypto/asn1/a_sign.o" =>
                [
                    "../openssl/crypto/asn1/a_sign.c",
                ],
            "crypto/asn1/a_strex.o" =>
                [
                    "../openssl/crypto/asn1/a_strex.c",
                ],
            "crypto/asn1/a_strnid.o" =>
                [
                    "../openssl/crypto/asn1/a_strnid.c",
                ],
            "crypto/asn1/a_time.o" =>
                [
                    "../openssl/crypto/asn1/a_time.c",
                ],
            "crypto/asn1/a_type.o" =>
                [
                    "../openssl/crypto/asn1/a_type.c",
                ],
            "crypto/asn1/a_utctm.o" =>
                [
                    "../openssl/crypto/asn1/a_utctm.c",
                ],
            "crypto/asn1/a_utf8.o" =>
                [
                    "../openssl/crypto/asn1/a_utf8.c",
                ],
            "crypto/asn1/a_verify.o" =>
                [
                    "../openssl/crypto/asn1/a_verify.c",
                ],
            "crypto/asn1/ameth_lib.o" =>
                [
                    "../openssl/crypto/asn1/ameth_lib.c",
                ],
            "crypto/asn1/asn1_err.o" =>
                [
                    "../openssl/crypto/asn1/asn1_err.c",
                ],
            "crypto/asn1/asn1_gen.o" =>
                [
                    "../openssl/crypto/asn1/asn1_gen.c",
                ],
            "crypto/asn1/asn1_item_list.o" =>
                [
                    "../openssl/crypto/asn1/asn1_item_list.c",
                ],
            "crypto/asn1/asn1_lib.o" =>
                [
                    "../openssl/crypto/asn1/asn1_lib.c",
                ],
            "crypto/asn1/asn1_par.o" =>
                [
                    "../openssl/crypto/asn1/asn1_par.c",
                ],
            "crypto/asn1/asn_mime.o" =>
                [
                    "../openssl/crypto/asn1/asn_mime.c",
                ],
            "crypto/asn1/asn_moid.o" =>
                [
                    "../openssl/crypto/asn1/asn_moid.c",
                ],
            "crypto/asn1/asn_mstbl.o" =>
                [
                    "../openssl/crypto/asn1/asn_mstbl.c",
                ],
            "crypto/asn1/asn_pack.o" =>
                [
                    "../openssl/crypto/asn1/asn_pack.c",
                ],
            "crypto/asn1/bio_asn1.o" =>
                [
                    "../openssl/crypto/asn1/bio_asn1.c",
                ],
            "crypto/asn1/bio_ndef.o" =>
                [
                    "../openssl/crypto/asn1/bio_ndef.c",
                ],
            "crypto/asn1/d2i_pr.o" =>
                [
                    "../openssl/crypto/asn1/d2i_pr.c",
                ],
            "crypto/asn1/d2i_pu.o" =>
                [
                    "../openssl/crypto/asn1/d2i_pu.c",
                ],
            "crypto/asn1/evp_asn1.o" =>
                [
                    "../openssl/crypto/asn1/evp_asn1.c",
                ],
            "crypto/asn1/f_int.o" =>
                [
                    "../openssl/crypto/asn1/f_int.c",
                ],
            "crypto/asn1/f_string.o" =>
                [
                    "../openssl/crypto/asn1/f_string.c",
                ],
            "crypto/asn1/i2d_pr.o" =>
                [
                    "../openssl/crypto/asn1/i2d_pr.c",
                ],
            "crypto/asn1/i2d_pu.o" =>
                [
                    "../openssl/crypto/asn1/i2d_pu.c",
                ],
            "crypto/asn1/n_pkey.o" =>
                [
                    "../openssl/crypto/asn1/n_pkey.c",
                ],
            "crypto/asn1/nsseq.o" =>
                [
                    "../openssl/crypto/asn1/nsseq.c",
                ],
            "crypto/asn1/p5_pbe.o" =>
                [
                    "../openssl/crypto/asn1/p5_pbe.c",
                ],
            "crypto/asn1/p5_pbev2.o" =>
                [
                    "../openssl/crypto/asn1/p5_pbev2.c",
                ],
            "crypto/asn1/p5_scrypt.o" =>
                [
                    "../openssl/crypto/asn1/p5_scrypt.c",
                ],
            "crypto/asn1/p8_pkey.o" =>
                [
                    "../openssl/crypto/asn1/p8_pkey.c",
                ],
            "crypto/asn1/t_bitst.o" =>
                [
                    "../openssl/crypto/asn1/t_bitst.c",
                ],
            "crypto/asn1/t_pkey.o" =>
                [
                    "../openssl/crypto/asn1/t_pkey.c",
                ],
            "crypto/asn1/t_spki.o" =>
                [
                    "../openssl/crypto/asn1/t_spki.c",
                ],
            "crypto/asn1/tasn_dec.o" =>
                [
                    "../openssl/crypto/asn1/tasn_dec.c",
                ],
            "crypto/asn1/tasn_enc.o" =>
                [
                    "../openssl/crypto/asn1/tasn_enc.c",
                ],
            "crypto/asn1/tasn_fre.o" =>
                [
                    "../openssl/crypto/asn1/tasn_fre.c",
                ],
            "crypto/asn1/tasn_new.o" =>
                [
                    "../openssl/crypto/asn1/tasn_new.c",
                ],
            "crypto/asn1/tasn_prn.o" =>
                [
                    "../openssl/crypto/asn1/tasn_prn.c",
                ],
            "crypto/asn1/tasn_scn.o" =>
                [
                    "../openssl/crypto/asn1/tasn_scn.c",
                ],
            "crypto/asn1/tasn_typ.o" =>
                [
                    "../openssl/crypto/asn1/tasn_typ.c",
                ],
            "crypto/asn1/tasn_utl.o" =>
                [
                    "../openssl/crypto/asn1/tasn_utl.c",
                ],
            "crypto/asn1/x_algor.o" =>
                [
                    "../openssl/crypto/asn1/x_algor.c",
                ],
            "crypto/asn1/x_bignum.o" =>
                [
                    "../openssl/crypto/asn1/x_bignum.c",
                ],
            "crypto/asn1/x_info.o" =>
                [
                    "../openssl/crypto/asn1/x_info.c",
                ],
            "crypto/asn1/x_int64.o" =>
                [
                    "../openssl/crypto/asn1/x_int64.c",
                ],
            "crypto/asn1/x_long.o" =>
                [
                    "../openssl/crypto/asn1/x_long.c",
                ],
            "crypto/asn1/x_pkey.o" =>
                [
                    "../openssl/crypto/asn1/x_pkey.c",
                ],
            "crypto/asn1/x_sig.o" =>
                [
                    "../openssl/crypto/asn1/x_sig.c",
                ],
            "crypto/asn1/x_spki.o" =>
                [
                    "../openssl/crypto/asn1/x_spki.c",
                ],
            "crypto/asn1/x_val.o" =>
                [
                    "../openssl/crypto/asn1/x_val.c",
                ],
            "crypto/async/arch/async_null.o" =>
                [
                    "../openssl/crypto/async/arch/async_null.c",
                ],
            "crypto/async/arch/async_posix.o" =>
                [
                    "../openssl/crypto/async/arch/async_posix.c",
                ],
            "crypto/async/arch/async_win.o" =>
                [
                    "../openssl/crypto/async/arch/async_win.c",
                ],
            "crypto/async/async.o" =>
                [
                    "../openssl/crypto/async/async.c",
                ],
            "crypto/async/async_err.o" =>
                [
                    "../openssl/crypto/async/async_err.c",
                ],
            "crypto/async/async_wait.o" =>
                [
                    "../openssl/crypto/async/async_wait.c",
                ],
            "crypto/bio/b_addr.o" =>
                [
                    "../openssl/crypto/bio/b_addr.c",
                ],
            "crypto/bio/b_dump.o" =>
                [
                    "../openssl/crypto/bio/b_dump.c",
                ],
            "crypto/bio/b_print.o" =>
                [
                    "../openssl/crypto/bio/b_print.c",
                ],
            "crypto/bio/b_sock.o" =>
                [
                    "../openssl/crypto/bio/b_sock.c",
                ],
            "crypto/bio/b_sock2.o" =>
                [
                    "../openssl/crypto/bio/b_sock2.c",
                ],
            "crypto/bio/bf_buff.o" =>
                [
                    "../openssl/crypto/bio/bf_buff.c",
                ],
            "crypto/bio/bf_lbuf.o" =>
                [
                    "../openssl/crypto/bio/bf_lbuf.c",
                ],
            "crypto/bio/bf_nbio.o" =>
                [
                    "../openssl/crypto/bio/bf_nbio.c",
                ],
            "crypto/bio/bf_null.o" =>
                [
                    "../openssl/crypto/bio/bf_null.c",
                ],
            "crypto/bio/bio_cb.o" =>
                [
                    "../openssl/crypto/bio/bio_cb.c",
                ],
            "crypto/bio/bio_err.o" =>
                [
                    "../openssl/crypto/bio/bio_err.c",
                ],
            "crypto/bio/bio_lib.o" =>
                [
                    "../openssl/crypto/bio/bio_lib.c",
                ],
            "crypto/bio/bio_meth.o" =>
                [
                    "../openssl/crypto/bio/bio_meth.c",
                ],
            "crypto/bio/bss_acpt.o" =>
                [
                    "../openssl/crypto/bio/bss_acpt.c",
                ],
            "crypto/bio/bss_bio.o" =>
                [
                    "../openssl/crypto/bio/bss_bio.c",
                ],
            "crypto/bio/bss_conn.o" =>
                [
                    "../openssl/crypto/bio/bss_conn.c",
                ],
            "crypto/bio/bss_dgram.o" =>
                [
                    "../openssl/crypto/bio/bss_dgram.c",
                ],
            "crypto/bio/bss_fd.o" =>
                [
                    "../openssl/crypto/bio/bss_fd.c",
                ],
            "crypto/bio/bss_file.o" =>
                [
                    "../openssl/crypto/bio/bss_file.c",
                ],
            "crypto/bio/bss_log.o" =>
                [
                    "../openssl/crypto/bio/bss_log.c",
                ],
            "crypto/bio/bss_mem.o" =>
                [
                    "../openssl/crypto/bio/bss_mem.c",
                ],
            "crypto/bio/bss_null.o" =>
                [
                    "../openssl/crypto/bio/bss_null.c",
                ],
            "crypto/bio/bss_sock.o" =>
                [
                    "../openssl/crypto/bio/bss_sock.c",
                ],
            "crypto/bn/bn_add.o" =>
                [
                    "../openssl/crypto/bn/bn_add.c",
                ],
            "crypto/bn/bn_asm.o" =>
                [
                    "../openssl/crypto/bn/bn_asm.c",
                ],
            "crypto/bn/bn_blind.o" =>
                [
                    "../openssl/crypto/bn/bn_blind.c",
                ],
            "crypto/bn/bn_const.o" =>
                [
                    "../openssl/crypto/bn/bn_const.c",
                ],
            "crypto/bn/bn_ctx.o" =>
                [
                    "../openssl/crypto/bn/bn_ctx.c",
                ],
            "crypto/bn/bn_depr.o" =>
                [
                    "../openssl/crypto/bn/bn_depr.c",
                ],
            "crypto/bn/bn_dh.o" =>
                [
                    "../openssl/crypto/bn/bn_dh.c",
                ],
            "crypto/bn/bn_div.o" =>
                [
                    "../openssl/crypto/bn/bn_div.c",
                ],
            "crypto/bn/bn_err.o" =>
                [
                    "../openssl/crypto/bn/bn_err.c",
                ],
            "crypto/bn/bn_exp.o" =>
                [
                    "../openssl/crypto/bn/bn_exp.c",
                ],
            "crypto/bn/bn_exp2.o" =>
                [
                    "../openssl/crypto/bn/bn_exp2.c",
                ],
            "crypto/bn/bn_gcd.o" =>
                [
                    "../openssl/crypto/bn/bn_gcd.c",
                ],
            "crypto/bn/bn_gf2m.o" =>
                [
                    "../openssl/crypto/bn/bn_gf2m.c",
                ],
            "crypto/bn/bn_intern.o" =>
                [
                    "../openssl/crypto/bn/bn_intern.c",
                ],
            "crypto/bn/bn_kron.o" =>
                [
                    "../openssl/crypto/bn/bn_kron.c",
                ],
            "crypto/bn/bn_lib.o" =>
                [
                    "../openssl/crypto/bn/bn_lib.c",
                ],
            "crypto/bn/bn_mod.o" =>
                [
                    "../openssl/crypto/bn/bn_mod.c",
                ],
            "crypto/bn/bn_mont.o" =>
                [
                    "../openssl/crypto/bn/bn_mont.c",
                ],
            "crypto/bn/bn_mpi.o" =>
                [
                    "../openssl/crypto/bn/bn_mpi.c",
                ],
            "crypto/bn/bn_mul.o" =>
                [
                    "../openssl/crypto/bn/bn_mul.c",
                ],
            "crypto/bn/bn_nist.o" =>
                [
                    "../openssl/crypto/bn/bn_nist.c",
                ],
            "crypto/bn/bn_prime.o" =>
                [
                    "../openssl/crypto/bn/bn_prime.c",
                ],
            "crypto/bn/bn_print.o" =>
                [
                    "../openssl/crypto/bn/bn_print.c",
                ],
            "crypto/bn/bn_rand.o" =>
                [
                    "../openssl/crypto/bn/bn_rand.c",
                ],
            "crypto/bn/bn_recp.o" =>
                [
                    "../openssl/crypto/bn/bn_recp.c",
                ],
            "crypto/bn/bn_shift.o" =>
                [
                    "../openssl/crypto/bn/bn_shift.c",
                ],
            "crypto/bn/bn_sqr.o" =>
                [
                    "../openssl/crypto/bn/bn_sqr.c",
                ],
            "crypto/bn/bn_sqrt.o" =>
                [
                    "../openssl/crypto/bn/bn_sqrt.c",
                ],
            "crypto/bn/bn_srp.o" =>
                [
                    "../openssl/crypto/bn/bn_srp.c",
                ],
            "crypto/bn/bn_word.o" =>
                [
                    "../openssl/crypto/bn/bn_word.c",
                ],
            "crypto/bn/bn_x931p.o" =>
                [
                    "../openssl/crypto/bn/bn_x931p.c",
                ],
            "crypto/buffer/buf_err.o" =>
                [
                    "../openssl/crypto/buffer/buf_err.c",
                ],
            "crypto/buffer/buffer.o" =>
                [
                    "../openssl/crypto/buffer/buffer.c",
                ],
            "crypto/camellia/camellia.o" =>
                [
                    "../openssl/crypto/camellia/camellia.c",
                ],
            "crypto/camellia/cmll_cbc.o" =>
                [
                    "../openssl/crypto/camellia/cmll_cbc.c",
                ],
            "crypto/camellia/cmll_cfb.o" =>
                [
                    "../openssl/crypto/camellia/cmll_cfb.c",
                ],
            "crypto/camellia/cmll_ctr.o" =>
                [
                    "../openssl/crypto/camellia/cmll_ctr.c",
                ],
            "crypto/camellia/cmll_ecb.o" =>
                [
                    "../openssl/crypto/camellia/cmll_ecb.c",
                ],
            "crypto/camellia/cmll_misc.o" =>
                [
                    "../openssl/crypto/camellia/cmll_misc.c",
                ],
            "crypto/camellia/cmll_ofb.o" =>
                [
                    "../openssl/crypto/camellia/cmll_ofb.c",
                ],
            "crypto/cmac/cm_ameth.o" =>
                [
                    "../openssl/crypto/cmac/cm_ameth.c",
                ],
            "crypto/cmac/cm_pmeth.o" =>
                [
                    "../openssl/crypto/cmac/cm_pmeth.c",
                ],
            "crypto/cmac/cmac.o" =>
                [
                    "../openssl/crypto/cmac/cmac.c",
                ],
            "crypto/conf/conf_api.o" =>
                [
                    "../openssl/crypto/conf/conf_api.c",
                ],
            "crypto/conf/conf_def.o" =>
                [
                    "../openssl/crypto/conf/conf_def.c",
                ],
            "crypto/conf/conf_err.o" =>
                [
                    "../openssl/crypto/conf/conf_err.c",
                ],
            "crypto/conf/conf_lib.o" =>
                [
                    "../openssl/crypto/conf/conf_lib.c",
                ],
            "crypto/conf/conf_mall.o" =>
                [
                    "../openssl/crypto/conf/conf_mall.c",
                ],
            "crypto/conf/conf_mod.o" =>
                [
                    "../openssl/crypto/conf/conf_mod.c",
                ],
            "crypto/conf/conf_sap.o" =>
                [
                    "../openssl/crypto/conf/conf_sap.c",
                ],
            "crypto/conf/conf_ssl.o" =>
                [
                    "../openssl/crypto/conf/conf_ssl.c",
                ],
            "crypto/cpt_err.o" =>
                [
                    "../openssl/crypto/cpt_err.c",
                ],
            "crypto/cryptlib.o" =>
                [
                    "../openssl/crypto/cryptlib.c",
                ],
            "crypto/ctype.o" =>
                [
                    "../openssl/crypto/ctype.c",
                ],
            "crypto/cversion.o" =>
                [
                    "../openssl/crypto/cversion.c",
                ],
            "crypto/des/cbc_cksm.o" =>
                [
                    "../openssl/crypto/des/cbc_cksm.c",
                ],
            "crypto/des/cbc_enc.o" =>
                [
                    "../openssl/crypto/des/cbc_enc.c",
                ],
            "crypto/des/cfb64ede.o" =>
                [
                    "../openssl/crypto/des/cfb64ede.c",
                ],
            "crypto/des/cfb64enc.o" =>
                [
                    "../openssl/crypto/des/cfb64enc.c",
                ],
            "crypto/des/cfb_enc.o" =>
                [
                    "../openssl/crypto/des/cfb_enc.c",
                ],
            "crypto/des/des_enc.o" =>
                [
                    "../openssl/crypto/des/des_enc.c",
                ],
            "crypto/des/ecb3_enc.o" =>
                [
                    "../openssl/crypto/des/ecb3_enc.c",
                ],
            "crypto/des/ecb_enc.o" =>
                [
                    "../openssl/crypto/des/ecb_enc.c",
                ],
            "crypto/des/fcrypt.o" =>
                [
                    "../openssl/crypto/des/fcrypt.c",
                ],
            "crypto/des/fcrypt_b.o" =>
                [
                    "../openssl/crypto/des/fcrypt_b.c",
                ],
            "crypto/des/ofb64ede.o" =>
                [
                    "../openssl/crypto/des/ofb64ede.c",
                ],
            "crypto/des/ofb64enc.o" =>
                [
                    "../openssl/crypto/des/ofb64enc.c",
                ],
            "crypto/des/ofb_enc.o" =>
                [
                    "../openssl/crypto/des/ofb_enc.c",
                ],
            "crypto/des/pcbc_enc.o" =>
                [
                    "../openssl/crypto/des/pcbc_enc.c",
                ],
            "crypto/des/qud_cksm.o" =>
                [
                    "../openssl/crypto/des/qud_cksm.c",
                ],
            "crypto/des/rand_key.o" =>
                [
                    "../openssl/crypto/des/rand_key.c",
                ],
            "crypto/des/set_key.o" =>
                [
                    "../openssl/crypto/des/set_key.c",
                ],
            "crypto/des/str2key.o" =>
                [
                    "../openssl/crypto/des/str2key.c",
                ],
            "crypto/des/xcbc_enc.o" =>
                [
                    "../openssl/crypto/des/xcbc_enc.c",
                ],
            "crypto/dh/dh_ameth.o" =>
                [
                    "../openssl/crypto/dh/dh_ameth.c",
                ],
            "crypto/dh/dh_asn1.o" =>
                [
                    "../openssl/crypto/dh/dh_asn1.c",
                ],
            "crypto/dh/dh_check.o" =>
                [
                    "../openssl/crypto/dh/dh_check.c",
                ],
            "crypto/dh/dh_depr.o" =>
                [
                    "../openssl/crypto/dh/dh_depr.c",
                ],
            "crypto/dh/dh_err.o" =>
                [
                    "../openssl/crypto/dh/dh_err.c",
                ],
            "crypto/dh/dh_gen.o" =>
                [
                    "../openssl/crypto/dh/dh_gen.c",
                ],
            "crypto/dh/dh_kdf.o" =>
                [
                    "../openssl/crypto/dh/dh_kdf.c",
                ],
            "crypto/dh/dh_key.o" =>
                [
                    "../openssl/crypto/dh/dh_key.c",
                ],
            "crypto/dh/dh_lib.o" =>
                [
                    "../openssl/crypto/dh/dh_lib.c",
                ],
            "crypto/dh/dh_meth.o" =>
                [
                    "../openssl/crypto/dh/dh_meth.c",
                ],
            "crypto/dh/dh_pmeth.o" =>
                [
                    "../openssl/crypto/dh/dh_pmeth.c",
                ],
            "crypto/dh/dh_prn.o" =>
                [
                    "../openssl/crypto/dh/dh_prn.c",
                ],
            "crypto/dh/dh_rfc5114.o" =>
                [
                    "../openssl/crypto/dh/dh_rfc5114.c",
                ],
            "crypto/dh/dh_rfc7919.o" =>
                [
                    "../openssl/crypto/dh/dh_rfc7919.c",
                ],
            "crypto/dso/dso_dl.o" =>
                [
                    "../openssl/crypto/dso/dso_dl.c",
                ],
            "crypto/dso/dso_dlfcn.o" =>
                [
                    "../openssl/crypto/dso/dso_dlfcn.c",
                ],
            "crypto/dso/dso_err.o" =>
                [
                    "../openssl/crypto/dso/dso_err.c",
                ],
            "crypto/dso/dso_lib.o" =>
                [
                    "../openssl/crypto/dso/dso_lib.c",
                ],
            "crypto/dso/dso_openssl.o" =>
                [
                    "../openssl/crypto/dso/dso_openssl.c",
                ],
            "crypto/dso/dso_vms.o" =>
                [
                    "../openssl/crypto/dso/dso_vms.c",
                ],
            "crypto/dso/dso_win32.o" =>
                [
                    "../openssl/crypto/dso/dso_win32.c",
                ],
            "crypto/ebcdic.o" =>
                [
                    "../openssl/crypto/ebcdic.c",
                ],
            "crypto/ec/curve25519.o" =>
                [
                    "../openssl/crypto/ec/curve25519.c",
                ],
            "crypto/ec/curve448/arch_32/f_impl.o" =>
                [
                    "../openssl/crypto/ec/curve448/arch_32/f_impl.c",
                ],
            "crypto/ec/curve448/curve448.o" =>
                [
                    "../openssl/crypto/ec/curve448/curve448.c",
                ],
            "crypto/ec/curve448/curve448_tables.o" =>
                [
                    "../openssl/crypto/ec/curve448/curve448_tables.c",
                ],
            "crypto/ec/curve448/eddsa.o" =>
                [
                    "../openssl/crypto/ec/curve448/eddsa.c",
                ],
            "crypto/ec/curve448/f_generic.o" =>
                [
                    "../openssl/crypto/ec/curve448/f_generic.c",
                ],
            "crypto/ec/curve448/scalar.o" =>
                [
                    "../openssl/crypto/ec/curve448/scalar.c",
                ],
            "crypto/ec/ec2_oct.o" =>
                [
                    "../openssl/crypto/ec/ec2_oct.c",
                ],
            "crypto/ec/ec2_smpl.o" =>
                [
                    "../openssl/crypto/ec/ec2_smpl.c",
                ],
            "crypto/ec/ec_ameth.o" =>
                [
                    "../openssl/crypto/ec/ec_ameth.c",
                ],
            "crypto/ec/ec_asn1.o" =>
                [
                    "../openssl/crypto/ec/ec_asn1.c",
                ],
            "crypto/ec/ec_check.o" =>
                [
                    "../openssl/crypto/ec/ec_check.c",
                ],
            "crypto/ec/ec_curve.o" =>
                [
                    "../openssl/crypto/ec/ec_curve.c",
                ],
            "crypto/ec/ec_cvt.o" =>
                [
                    "../openssl/crypto/ec/ec_cvt.c",
                ],
            "crypto/ec/ec_err.o" =>
                [
                    "../openssl/crypto/ec/ec_err.c",
                ],
            "crypto/ec/ec_key.o" =>
                [
                    "../openssl/crypto/ec/ec_key.c",
                ],
            "crypto/ec/ec_kmeth.o" =>
                [
                    "../openssl/crypto/ec/ec_kmeth.c",
                ],
            "crypto/ec/ec_lib.o" =>
                [
                    "../openssl/crypto/ec/ec_lib.c",
                ],
            "crypto/ec/ec_mult.o" =>
                [
                    "../openssl/crypto/ec/ec_mult.c",
                ],
            "crypto/ec/ec_oct.o" =>
                [
                    "../openssl/crypto/ec/ec_oct.c",
                ],
            "crypto/ec/ec_pmeth.o" =>
                [
                    "../openssl/crypto/ec/ec_pmeth.c",
                ],
            "crypto/ec/ec_print.o" =>
                [
                    "../openssl/crypto/ec/ec_print.c",
                ],
            "crypto/ec/ecdh_kdf.o" =>
                [
                    "../openssl/crypto/ec/ecdh_kdf.c",
                ],
            "crypto/ec/ecdh_ossl.o" =>
                [
                    "../openssl/crypto/ec/ecdh_ossl.c",
                ],
            "crypto/ec/ecdsa_ossl.o" =>
                [
                    "../openssl/crypto/ec/ecdsa_ossl.c",
                ],
            "crypto/ec/ecdsa_sign.o" =>
                [
                    "../openssl/crypto/ec/ecdsa_sign.c",
                ],
            "crypto/ec/ecdsa_vrf.o" =>
                [
                    "../openssl/crypto/ec/ecdsa_vrf.c",
                ],
            "crypto/ec/eck_prn.o" =>
                [
                    "../openssl/crypto/ec/eck_prn.c",
                ],
            "crypto/ec/ecp_mont.o" =>
                [
                    "../openssl/crypto/ec/ecp_mont.c",
                ],
            "crypto/ec/ecp_nist.o" =>
                [
                    "../openssl/crypto/ec/ecp_nist.c",
                ],
            "crypto/ec/ecp_nistp224.o" =>
                [
                    "../openssl/crypto/ec/ecp_nistp224.c",
                ],
            "crypto/ec/ecp_nistp256.o" =>
                [
                    "../openssl/crypto/ec/ecp_nistp256.c",
                ],
            "crypto/ec/ecp_nistp521.o" =>
                [
                    "../openssl/crypto/ec/ecp_nistp521.c",
                ],
            "crypto/ec/ecp_nistputil.o" =>
                [
                    "../openssl/crypto/ec/ecp_nistputil.c",
                ],
            "crypto/ec/ecp_oct.o" =>
                [
                    "../openssl/crypto/ec/ecp_oct.c",
                ],
            "crypto/ec/ecp_smpl.o" =>
                [
                    "../openssl/crypto/ec/ecp_smpl.c",
                ],
            "crypto/ec/ecx_meth.o" =>
                [
                    "../openssl/crypto/ec/ecx_meth.c",
                ],
            "crypto/err/err.o" =>
                [
                    "../openssl/crypto/err/err.c",
                ],
            "crypto/err/err_all.o" =>
                [
                    "../openssl/crypto/err/err_all.c",
                ],
            "crypto/err/err_prn.o" =>
                [
                    "../openssl/crypto/err/err_prn.c",
                ],
            "crypto/evp/bio_b64.o" =>
                [
                    "../openssl/crypto/evp/bio_b64.c",
                ],
            "crypto/evp/bio_enc.o" =>
                [
                    "../openssl/crypto/evp/bio_enc.c",
                ],
            "crypto/evp/bio_md.o" =>
                [
                    "../openssl/crypto/evp/bio_md.c",
                ],
            "crypto/evp/bio_ok.o" =>
                [
                    "../openssl/crypto/evp/bio_ok.c",
                ],
            "crypto/evp/c_allc.o" =>
                [
                    "../openssl/crypto/evp/c_allc.c",
                ],
            "crypto/evp/c_alld.o" =>
                [
                    "../openssl/crypto/evp/c_alld.c",
                ],
            "crypto/evp/cmeth_lib.o" =>
                [
                    "../openssl/crypto/evp/cmeth_lib.c",
                ],
            "crypto/evp/digest.o" =>
                [
                    "../openssl/crypto/evp/digest.c",
                ],
            "crypto/evp/e_aes.o" =>
                [
                    "../openssl/crypto/evp/e_aes.c",
                ],
            "crypto/evp/e_aes_cbc_hmac_sha1.o" =>
                [
                    "../openssl/crypto/evp/e_aes_cbc_hmac_sha1.c",
                ],
            "crypto/evp/e_aes_cbc_hmac_sha256.o" =>
                [
                    "../openssl/crypto/evp/e_aes_cbc_hmac_sha256.c",
                ],
            "crypto/evp/e_aria.o" =>
                [
                    "../openssl/crypto/evp/e_aria.c",
                ],
            "crypto/evp/e_bf.o" =>
                [
                    "../openssl/crypto/evp/e_bf.c",
                ],
            "crypto/evp/e_camellia.o" =>
                [
                    "../openssl/crypto/evp/e_camellia.c",
                ],
            "crypto/evp/e_cast.o" =>
                [
                    "../openssl/crypto/evp/e_cast.c",
                ],
            "crypto/evp/e_chacha20_poly1305.o" =>
                [
                    "../openssl/crypto/evp/e_chacha20_poly1305.c",
                ],
            "crypto/evp/e_des.o" =>
                [
                    "../openssl/crypto/evp/e_des.c",
                ],
            "crypto/evp/e_des3.o" =>
                [
                    "../openssl/crypto/evp/e_des3.c",
                ],
            "crypto/evp/e_idea.o" =>
                [
                    "../openssl/crypto/evp/e_idea.c",
                ],
            "crypto/evp/e_null.o" =>
                [
                    "../openssl/crypto/evp/e_null.c",
                ],
            "crypto/evp/e_old.o" =>
                [
                    "../openssl/crypto/evp/e_old.c",
                ],
            "crypto/evp/e_rc2.o" =>
                [
                    "../openssl/crypto/evp/e_rc2.c",
                ],
            "crypto/evp/e_rc4.o" =>
                [
                    "../openssl/crypto/evp/e_rc4.c",
                ],
            "crypto/evp/e_rc4_hmac_md5.o" =>
                [
                    "../openssl/crypto/evp/e_rc4_hmac_md5.c",
                ],
            "crypto/evp/e_rc5.o" =>
                [
                    "../openssl/crypto/evp/e_rc5.c",
                ],
            "crypto/evp/e_seed.o" =>
                [
                    "../openssl/crypto/evp/e_seed.c",
                ],
            "crypto/evp/e_sm4.o" =>
                [
                    "../openssl/crypto/evp/e_sm4.c",
                ],
            "crypto/evp/e_xcbc_d.o" =>
                [
                    "../openssl/crypto/evp/e_xcbc_d.c",
                ],
            "crypto/evp/encode.o" =>
                [
                    "../openssl/crypto/evp/encode.c",
                ],
            "crypto/evp/evp_cnf.o" =>
                [
                    "../openssl/crypto/evp/evp_cnf.c",
                ],
            "crypto/evp/evp_enc.o" =>
                [
                    "../openssl/crypto/evp/evp_enc.c",
                ],
            "crypto/evp/evp_err.o" =>
                [
                    "../openssl/crypto/evp/evp_err.c",
                ],
            "crypto/evp/evp_key.o" =>
                [
                    "../openssl/crypto/evp/evp_key.c",
                ],
            "crypto/evp/evp_lib.o" =>
                [
                    "../openssl/crypto/evp/evp_lib.c",
                ],
            "crypto/evp/evp_pbe.o" =>
                [
                    "../openssl/crypto/evp/evp_pbe.c",
                ],
            "crypto/evp/evp_pkey.o" =>
                [
                    "../openssl/crypto/evp/evp_pkey.c",
                ],
            "crypto/evp/m_md2.o" =>
                [
                    "../openssl/crypto/evp/m_md2.c",
                ],
            "crypto/evp/m_md4.o" =>
                [
                    "../openssl/crypto/evp/m_md4.c",
                ],
            "crypto/evp/m_md5.o" =>
                [
                    "../openssl/crypto/evp/m_md5.c",
                ],
            "crypto/evp/m_md5_sha1.o" =>
                [
                    "../openssl/crypto/evp/m_md5_sha1.c",
                ],
            "crypto/evp/m_mdc2.o" =>
                [
                    "../openssl/crypto/evp/m_mdc2.c",
                ],
            "crypto/evp/m_null.o" =>
                [
                    "../openssl/crypto/evp/m_null.c",
                ],
            "crypto/evp/m_ripemd.o" =>
                [
                    "../openssl/crypto/evp/m_ripemd.c",
                ],
            "crypto/evp/m_sha1.o" =>
                [
                    "../openssl/crypto/evp/m_sha1.c",
                ],
            "crypto/evp/m_sha3.o" =>
                [
                    "../openssl/crypto/evp/m_sha3.c",
                ],
            "crypto/evp/m_sigver.o" =>
                [
                    "../openssl/crypto/evp/m_sigver.c",
                ],
            "crypto/evp/m_wp.o" =>
                [
                    "../openssl/crypto/evp/m_wp.c",
                ],
            "crypto/evp/names.o" =>
                [
                    "../openssl/crypto/evp/names.c",
                ],
            "crypto/evp/p5_crpt.o" =>
                [
                    "../openssl/crypto/evp/p5_crpt.c",
                ],
            "crypto/evp/p5_crpt2.o" =>
                [
                    "../openssl/crypto/evp/p5_crpt2.c",
                ],
            "crypto/evp/p_dec.o" =>
                [
                    "../openssl/crypto/evp/p_dec.c",
                ],
            "crypto/evp/p_enc.o" =>
                [
                    "../openssl/crypto/evp/p_enc.c",
                ],
            "crypto/evp/p_lib.o" =>
                [
                    "../openssl/crypto/evp/p_lib.c",
                ],
            "crypto/evp/p_open.o" =>
                [
                    "../openssl/crypto/evp/p_open.c",
                ],
            "crypto/evp/p_seal.o" =>
                [
                    "../openssl/crypto/evp/p_seal.c",
                ],
            "crypto/evp/p_sign.o" =>
                [
                    "../openssl/crypto/evp/p_sign.c",
                ],
            "crypto/evp/p_verify.o" =>
                [
                    "../openssl/crypto/evp/p_verify.c",
                ],
            "crypto/evp/pbe_scrypt.o" =>
                [
                    "../openssl/crypto/evp/pbe_scrypt.c",
                ],
            "crypto/evp/pmeth_fn.o" =>
                [
                    "../openssl/crypto/evp/pmeth_fn.c",
                ],
            "crypto/evp/pmeth_gn.o" =>
                [
                    "../openssl/crypto/evp/pmeth_gn.c",
                ],
            "crypto/evp/pmeth_lib.o" =>
                [
                    "../openssl/crypto/evp/pmeth_lib.c",
                ],
            "crypto/ex_data.o" =>
                [
                    "../openssl/crypto/ex_data.c",
                ],
            "crypto/getenv.o" =>
                [
                    "../openssl/crypto/getenv.c",
                ],
            "crypto/hmac/hm_ameth.o" =>
                [
                    "../openssl/crypto/hmac/hm_ameth.c",
                ],
            "crypto/hmac/hm_pmeth.o" =>
                [
                    "../openssl/crypto/hmac/hm_pmeth.c",
                ],
            "crypto/hmac/hmac.o" =>
                [
                    "../openssl/crypto/hmac/hmac.c",
                ],
            "crypto/init.o" =>
                [
                    "../openssl/crypto/init.c",
                ],
            "crypto/kdf/hkdf.o" =>
                [
                    "../openssl/crypto/kdf/hkdf.c",
                ],
            "crypto/kdf/kdf_err.o" =>
                [
                    "../openssl/crypto/kdf/kdf_err.c",
                ],
            "crypto/kdf/scrypt.o" =>
                [
                    "../openssl/crypto/kdf/scrypt.c",
                ],
            "crypto/kdf/tls1_prf.o" =>
                [
                    "../openssl/crypto/kdf/tls1_prf.c",
                ],
            "crypto/lhash/lh_stats.o" =>
                [
                    "../openssl/crypto/lhash/lh_stats.c",
                ],
            "crypto/lhash/lhash.o" =>
                [
                    "../openssl/crypto/lhash/lhash.c",
                ],
            "crypto/md5/md5_dgst.o" =>
                [
                    "../openssl/crypto/md5/md5_dgst.c",
                ],
            "crypto/md5/md5_one.o" =>
                [
                    "../openssl/crypto/md5/md5_one.c",
                ],
            "crypto/mem.o" =>
                [
                    "../openssl/crypto/mem.c",
                ],
            "crypto/mem_clr.o" =>
                [
                    "../openssl/crypto/mem_clr.c",
                ],
            "crypto/mem_dbg.o" =>
                [
                    "../openssl/crypto/mem_dbg.c",
                ],
            "crypto/mem_sec.o" =>
                [
                    "../openssl/crypto/mem_sec.c",
                ],
            "crypto/modes/cbc128.o" =>
                [
                    "../openssl/crypto/modes/cbc128.c",
                ],
            "crypto/modes/ccm128.o" =>
                [
                    "../openssl/crypto/modes/ccm128.c",
                ],
            "crypto/modes/cfb128.o" =>
                [
                    "../openssl/crypto/modes/cfb128.c",
                ],
            "crypto/modes/ctr128.o" =>
                [
                    "../openssl/crypto/modes/ctr128.c",
                ],
            "crypto/modes/cts128.o" =>
                [
                    "../openssl/crypto/modes/cts128.c",
                ],
            "crypto/modes/gcm128.o" =>
                [
                    "../openssl/crypto/modes/gcm128.c",
                ],
            "crypto/modes/ocb128.o" =>
                [
                    "../openssl/crypto/modes/ocb128.c",
                ],
            "crypto/modes/ofb128.o" =>
                [
                    "../openssl/crypto/modes/ofb128.c",
                ],
            "crypto/modes/wrap128.o" =>
                [
                    "../openssl/crypto/modes/wrap128.c",
                ],
            "crypto/modes/xts128.o" =>
                [
                    "../openssl/crypto/modes/xts128.c",
                ],
            "crypto/o_dir.o" =>
                [
                    "../openssl/crypto/o_dir.c",
                ],
            "crypto/o_fips.o" =>
                [
                    "../openssl/crypto/o_fips.c",
                ],
            "crypto/o_fopen.o" =>
                [
                    "../openssl/crypto/o_fopen.c",
                ],
            "crypto/o_init.o" =>
                [
                    "../openssl/crypto/o_init.c",
                ],
            "crypto/o_str.o" =>
                [
                    "../openssl/crypto/o_str.c",
                ],
            "crypto/o_time.o" =>
                [
                    "../openssl/crypto/o_time.c",
                ],
            "crypto/objects/o_names.o" =>
                [
                    "../openssl/crypto/objects/o_names.c",
                ],
            "crypto/objects/obj_dat.o" =>
                [
                    "../openssl/crypto/objects/obj_dat.c",
                ],
            "crypto/objects/obj_err.o" =>
                [
                    "../openssl/crypto/objects/obj_err.c",
                ],
            "crypto/objects/obj_lib.o" =>
                [
                    "../openssl/crypto/objects/obj_lib.c",
                ],
            "crypto/objects/obj_xref.o" =>
                [
                    "../openssl/crypto/objects/obj_xref.c",
                ],
            "crypto/pem/pem_all.o" =>
                [
                    "../openssl/crypto/pem/pem_all.c",
                ],
            "crypto/pem/pem_err.o" =>
                [
                    "../openssl/crypto/pem/pem_err.c",
                ],
            "crypto/pem/pem_info.o" =>
                [
                    "../openssl/crypto/pem/pem_info.c",
                ],
            "crypto/pem/pem_lib.o" =>
                [
                    "../openssl/crypto/pem/pem_lib.c",
                ],
            "crypto/pem/pem_oth.o" =>
                [
                    "../openssl/crypto/pem/pem_oth.c",
                ],
            "crypto/pem/pem_pk8.o" =>
                [
                    "../openssl/crypto/pem/pem_pk8.c",
                ],
            "crypto/pem/pem_pkey.o" =>
                [
                    "../openssl/crypto/pem/pem_pkey.c",
                ],
            "crypto/pem/pem_sign.o" =>
                [
                    "../openssl/crypto/pem/pem_sign.c",
                ],
            "crypto/pem/pem_x509.o" =>
                [
                    "../openssl/crypto/pem/pem_x509.c",
                ],
            "crypto/pem/pem_xaux.o" =>
                [
                    "../openssl/crypto/pem/pem_xaux.c",
                ],
            "crypto/pem/pvkfmt.o" =>
                [
                    "../openssl/crypto/pem/pvkfmt.c",
                ],
            "crypto/pkcs12/p12_add.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_add.c",
                ],
            "crypto/pkcs12/p12_asn.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_asn.c",
                ],
            "crypto/pkcs12/p12_attr.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_attr.c",
                ],
            "crypto/pkcs12/p12_crpt.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_crpt.c",
                ],
            "crypto/pkcs12/p12_crt.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_crt.c",
                ],
            "crypto/pkcs12/p12_decr.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_decr.c",
                ],
            "crypto/pkcs12/p12_init.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_init.c",
                ],
            "crypto/pkcs12/p12_key.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_key.c",
                ],
            "crypto/pkcs12/p12_kiss.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_kiss.c",
                ],
            "crypto/pkcs12/p12_mutl.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_mutl.c",
                ],
            "crypto/pkcs12/p12_npas.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_npas.c",
                ],
            "crypto/pkcs12/p12_p8d.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_p8d.c",
                ],
            "crypto/pkcs12/p12_p8e.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_p8e.c",
                ],
            "crypto/pkcs12/p12_sbag.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_sbag.c",
                ],
            "crypto/pkcs12/p12_utl.o" =>
                [
                    "../openssl/crypto/pkcs12/p12_utl.c",
                ],
            "crypto/pkcs12/pk12err.o" =>
                [
                    "../openssl/crypto/pkcs12/pk12err.c",
                ],
            "crypto/pkcs7/bio_pk7.o" =>
                [
                    "../openssl/crypto/pkcs7/bio_pk7.c",
                ],
            "crypto/pkcs7/pk7_asn1.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_asn1.c",
                ],
            "crypto/pkcs7/pk7_attr.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_attr.c",
                ],
            "crypto/pkcs7/pk7_doit.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_doit.c",
                ],
            "crypto/pkcs7/pk7_lib.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_lib.c",
                ],
            "crypto/pkcs7/pk7_mime.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_mime.c",
                ],
            "crypto/pkcs7/pk7_smime.o" =>
                [
                    "../openssl/crypto/pkcs7/pk7_smime.c",
                ],
            "crypto/pkcs7/pkcs7err.o" =>
                [
                    "../openssl/crypto/pkcs7/pkcs7err.c",
                ],
            "crypto/rand/drbg_ctr.o" =>
                [
                    "../openssl/crypto/rand/drbg_ctr.c",
                ],
            "crypto/rand/drbg_lib.o" =>
                [
                    "../openssl/crypto/rand/drbg_lib.c",
                ],
            "crypto/rand/rand_egd.o" =>
                [
                    "../openssl/crypto/rand/rand_egd.c",
                ],
            "crypto/rand/rand_err.o" =>
                [
                    "../openssl/crypto/rand/rand_err.c",
                ],
            "crypto/rand/rand_lib.o" =>
                [
                    "../openssl/crypto/rand/rand_lib.c",
                ],
            "crypto/rand/rand_unix.o" =>
                [
                    "../openssl/crypto/rand/rand_unix.c",
                ],
            "crypto/rand/rand_vms.o" =>
                [
                    "../openssl/crypto/rand/rand_vms.c",
                ],
            "crypto/rand/rand_win.o" =>
                [
                    "../openssl/crypto/rand/rand_win.c",
                ],
            "crypto/rand/randfile.o" =>
                [
                    "../openssl/crypto/rand/randfile.c",
                ],
            "crypto/rc4/rc4_enc.o" =>
                [
                    "../openssl/crypto/rc4/rc4_enc.c",
                ],
            "crypto/rc4/rc4_skey.o" =>
                [
                    "../openssl/crypto/rc4/rc4_skey.c",
                ],
            "crypto/rsa/rsa_ameth.o" =>
                [
                    "../openssl/crypto/rsa/rsa_ameth.c",
                ],
            "crypto/rsa/rsa_asn1.o" =>
                [
                    "../openssl/crypto/rsa/rsa_asn1.c",
                ],
            "crypto/rsa/rsa_chk.o" =>
                [
                    "../openssl/crypto/rsa/rsa_chk.c",
                ],
            "crypto/rsa/rsa_crpt.o" =>
                [
                    "../openssl/crypto/rsa/rsa_crpt.c",
                ],
            "crypto/rsa/rsa_depr.o" =>
                [
                    "../openssl/crypto/rsa/rsa_depr.c",
                ],
            "crypto/rsa/rsa_err.o" =>
                [
                    "../openssl/crypto/rsa/rsa_err.c",
                ],
            "crypto/rsa/rsa_gen.o" =>
                [
                    "../openssl/crypto/rsa/rsa_gen.c",
                ],
            "crypto/rsa/rsa_lib.o" =>
                [
                    "../openssl/crypto/rsa/rsa_lib.c",
                ],
            "crypto/rsa/rsa_meth.o" =>
                [
                    "../openssl/crypto/rsa/rsa_meth.c",
                ],
            "crypto/rsa/rsa_mp.o" =>
                [
                    "../openssl/crypto/rsa/rsa_mp.c",
                ],
            "crypto/rsa/rsa_none.o" =>
                [
                    "../openssl/crypto/rsa/rsa_none.c",
                ],
            "crypto/rsa/rsa_oaep.o" =>
                [
                    "../openssl/crypto/rsa/rsa_oaep.c",
                ],
            "crypto/rsa/rsa_ossl.o" =>
                [
                    "../openssl/crypto/rsa/rsa_ossl.c",
                ],
            "crypto/rsa/rsa_pk1.o" =>
                [
                    "../openssl/crypto/rsa/rsa_pk1.c",
                ],
            "crypto/rsa/rsa_pmeth.o" =>
                [
                    "../openssl/crypto/rsa/rsa_pmeth.c",
                ],
            "crypto/rsa/rsa_prn.o" =>
                [
                    "../openssl/crypto/rsa/rsa_prn.c",
                ],
            "crypto/rsa/rsa_pss.o" =>
                [
                    "../openssl/crypto/rsa/rsa_pss.c",
                ],
            "crypto/rsa/rsa_saos.o" =>
                [
                    "../openssl/crypto/rsa/rsa_saos.c",
                ],
            "crypto/rsa/rsa_sign.o" =>
                [
                    "../openssl/crypto/rsa/rsa_sign.c",
                ],
            "crypto/rsa/rsa_ssl.o" =>
                [
                    "../openssl/crypto/rsa/rsa_ssl.c",
                ],
            "crypto/rsa/rsa_x931.o" =>
                [
                    "../openssl/crypto/rsa/rsa_x931.c",
                ],
            "crypto/rsa/rsa_x931g.o" =>
                [
                    "../openssl/crypto/rsa/rsa_x931g.c",
                ],
            "crypto/sha/keccak1600.o" =>
                [
                    "../openssl/crypto/sha/keccak1600.c",
                ],
            "crypto/sha/sha1_one.o" =>
                [
                    "../openssl/crypto/sha/sha1_one.c",
                ],
            "crypto/sha/sha1dgst.o" =>
                [
                    "../openssl/crypto/sha/sha1dgst.c",
                ],
            "crypto/sha/sha256.o" =>
                [
                    "../openssl/crypto/sha/sha256.c",
                ],
            "crypto/sha/sha512.o" =>
                [
                    "../openssl/crypto/sha/sha512.c",
                ],
            "crypto/siphash/siphash.o" =>
                [
                    "../openssl/crypto/siphash/siphash.c",
                ],
            "crypto/siphash/siphash_ameth.o" =>
                [
                    "../openssl/crypto/siphash/siphash_ameth.c",
                ],
            "crypto/siphash/siphash_pmeth.o" =>
                [
                    "../openssl/crypto/siphash/siphash_pmeth.c",
                ],
            "crypto/sm2/sm2_crypt.o" =>
                [
                    "../openssl/crypto/sm2/sm2_crypt.c",
                ],
            "crypto/sm2/sm2_err.o" =>
                [
                    "../openssl/crypto/sm2/sm2_err.c",
                ],
            "crypto/sm2/sm2_pmeth.o" =>
                [
                    "../openssl/crypto/sm2/sm2_pmeth.c",
                ],
            "crypto/sm2/sm2_sign.o" =>
                [
                    "../openssl/crypto/sm2/sm2_sign.c",
                ],
            "crypto/sm3/m_sm3.o" =>
                [
                    "../openssl/crypto/sm3/m_sm3.c",
                ],
            "crypto/sm3/sm3.o" =>
                [
                    "../openssl/crypto/sm3/sm3.c",
                ],
            "crypto/sm4/sm4.o" =>
                [
                    "../openssl/crypto/sm4/sm4.c",
                ],
            "crypto/stack/stack.o" =>
                [
                    "../openssl/crypto/stack/stack.c",
                ],
            "crypto/store/loader_file.o" =>
                [
                    "../openssl/crypto/store/loader_file.c",
                ],
            "crypto/store/store_err.o" =>
                [
                    "../openssl/crypto/store/store_err.c",
                ],
            "crypto/store/store_init.o" =>
                [
                    "../openssl/crypto/store/store_init.c",
                ],
            "crypto/store/store_lib.o" =>
                [
                    "../openssl/crypto/store/store_lib.c",
                ],
            "crypto/store/store_register.o" =>
                [
                    "../openssl/crypto/store/store_register.c",
                ],
            "crypto/store/store_strings.o" =>
                [
                    "../openssl/crypto/store/store_strings.c",
                ],
            "crypto/threads_none.o" =>
                [
                    "../openssl/crypto/threads_none.c",
                ],
            "crypto/threads_pthread.o" =>
                [
                    "../openssl/crypto/threads_pthread.c",
                ],
            "crypto/threads_win.o" =>
                [
                    "../openssl/crypto/threads_win.c",
                ],
            "crypto/txt_db/txt_db.o" =>
                [
                    "../openssl/crypto/txt_db/txt_db.c",
                ],
            "crypto/ui/ui_err.o" =>
                [
                    "../openssl/crypto/ui/ui_err.c",
                ],
            "crypto/ui/ui_lib.o" =>
                [
                    "../openssl/crypto/ui/ui_lib.c",
                ],
            "crypto/ui/ui_null.o" =>
                [
                    "../openssl/crypto/ui/ui_null.c",
                ],
            "crypto/ui/ui_openssl.o" =>
                [
                    "../openssl/crypto/ui/ui_openssl.c",
                ],
            "crypto/ui/ui_util.o" =>
                [
                    "../openssl/crypto/ui/ui_util.c",
                ],
            "crypto/uid.o" =>
                [
                    "../openssl/crypto/uid.c",
                ],
            "crypto/x509/by_dir.o" =>
                [
                    "../openssl/crypto/x509/by_dir.c",
                ],
            "crypto/x509/by_file.o" =>
                [
                    "../openssl/crypto/x509/by_file.c",
                ],
            "crypto/x509/t_crl.o" =>
                [
                    "../openssl/crypto/x509/t_crl.c",
                ],
            "crypto/x509/t_req.o" =>
                [
                    "../openssl/crypto/x509/t_req.c",
                ],
            "crypto/x509/t_x509.o" =>
                [
                    "../openssl/crypto/x509/t_x509.c",
                ],
            "crypto/x509/x509_att.o" =>
                [
                    "../openssl/crypto/x509/x509_att.c",
                ],
            "crypto/x509/x509_cmp.o" =>
                [
                    "../openssl/crypto/x509/x509_cmp.c",
                ],
            "crypto/x509/x509_d2.o" =>
                [
                    "../openssl/crypto/x509/x509_d2.c",
                ],
            "crypto/x509/x509_def.o" =>
                [
                    "../openssl/crypto/x509/x509_def.c",
                ],
            "crypto/x509/x509_err.o" =>
                [
                    "../openssl/crypto/x509/x509_err.c",
                ],
            "crypto/x509/x509_ext.o" =>
                [
                    "../openssl/crypto/x509/x509_ext.c",
                ],
            "crypto/x509/x509_lu.o" =>
                [
                    "../openssl/crypto/x509/x509_lu.c",
                ],
            "crypto/x509/x509_meth.o" =>
                [
                    "../openssl/crypto/x509/x509_meth.c",
                ],
            "crypto/x509/x509_obj.o" =>
                [
                    "../openssl/crypto/x509/x509_obj.c",
                ],
            "crypto/x509/x509_r2x.o" =>
                [
                    "../openssl/crypto/x509/x509_r2x.c",
                ],
            "crypto/x509/x509_req.o" =>
                [
                    "../openssl/crypto/x509/x509_req.c",
                ],
            "crypto/x509/x509_set.o" =>
                [
                    "../openssl/crypto/x509/x509_set.c",
                ],
            "crypto/x509/x509_trs.o" =>
                [
                    "../openssl/crypto/x509/x509_trs.c",
                ],
            "crypto/x509/x509_txt.o" =>
                [
                    "../openssl/crypto/x509/x509_txt.c",
                ],
            "crypto/x509/x509_v3.o" =>
                [
                    "../openssl/crypto/x509/x509_v3.c",
                ],
            "crypto/x509/x509_vfy.o" =>
                [
                    "../openssl/crypto/x509/x509_vfy.c",
                ],
            "crypto/x509/x509_vpm.o" =>
                [
                    "../openssl/crypto/x509/x509_vpm.c",
                ],
            "crypto/x509/x509cset.o" =>
                [
                    "../openssl/crypto/x509/x509cset.c",
                ],
            "crypto/x509/x509name.o" =>
                [
                    "../openssl/crypto/x509/x509name.c",
                ],
            "crypto/x509/x509rset.o" =>
                [
                    "../openssl/crypto/x509/x509rset.c",
                ],
            "crypto/x509/x509spki.o" =>
                [
                    "../openssl/crypto/x509/x509spki.c",
                ],
            "crypto/x509/x509type.o" =>
                [
                    "../openssl/crypto/x509/x509type.c",
                ],
            "crypto/x509/x_all.o" =>
                [
                    "../openssl/crypto/x509/x_all.c",
                ],
            "crypto/x509/x_attrib.o" =>
                [
                    "../openssl/crypto/x509/x_attrib.c",
                ],
            "crypto/x509/x_crl.o" =>
                [
                    "../openssl/crypto/x509/x_crl.c",
                ],
            "crypto/x509/x_exten.o" =>
                [
                    "../openssl/crypto/x509/x_exten.c",
                ],
            "crypto/x509/x_name.o" =>
                [
                    "../openssl/crypto/x509/x_name.c",
                ],
            "crypto/x509/x_pubkey.o" =>
                [
                    "../openssl/crypto/x509/x_pubkey.c",
                ],
            "crypto/x509/x_req.o" =>
                [
                    "../openssl/crypto/x509/x_req.c",
                ],
            "crypto/x509/x_x509.o" =>
                [
                    "../openssl/crypto/x509/x_x509.c",
                ],
            "crypto/x509/x_x509a.o" =>
                [
                    "../openssl/crypto/x509/x_x509a.c",
                ],
            "crypto/x509v3/pcy_cache.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_cache.c",
                ],
            "crypto/x509v3/pcy_data.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_data.c",
                ],
            "crypto/x509v3/pcy_lib.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_lib.c",
                ],
            "crypto/x509v3/pcy_map.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_map.c",
                ],
            "crypto/x509v3/pcy_node.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_node.c",
                ],
            "crypto/x509v3/pcy_tree.o" =>
                [
                    "../openssl/crypto/x509v3/pcy_tree.c",
                ],
            "crypto/x509v3/v3_addr.o" =>
                [
                    "../openssl/crypto/x509v3/v3_addr.c",
                ],
            "crypto/x509v3/v3_admis.o" =>
                [
                    "../openssl/crypto/x509v3/v3_admis.c",
                ],
            "crypto/x509v3/v3_akey.o" =>
                [
                    "../openssl/crypto/x509v3/v3_akey.c",
                ],
            "crypto/x509v3/v3_akeya.o" =>
                [
                    "../openssl/crypto/x509v3/v3_akeya.c",
                ],
            "crypto/x509v3/v3_alt.o" =>
                [
                    "../openssl/crypto/x509v3/v3_alt.c",
                ],
            "crypto/x509v3/v3_asid.o" =>
                [
                    "../openssl/crypto/x509v3/v3_asid.c",
                ],
            "crypto/x509v3/v3_bcons.o" =>
                [
                    "../openssl/crypto/x509v3/v3_bcons.c",
                ],
            "crypto/x509v3/v3_bitst.o" =>
                [
                    "../openssl/crypto/x509v3/v3_bitst.c",
                ],
            "crypto/x509v3/v3_conf.o" =>
                [
                    "../openssl/crypto/x509v3/v3_conf.c",
                ],
            "crypto/x509v3/v3_cpols.o" =>
                [
                    "../openssl/crypto/x509v3/v3_cpols.c",
                ],
            "crypto/x509v3/v3_crld.o" =>
                [
                    "../openssl/crypto/x509v3/v3_crld.c",
                ],
            "crypto/x509v3/v3_enum.o" =>
                [
                    "../openssl/crypto/x509v3/v3_enum.c",
                ],
            "crypto/x509v3/v3_extku.o" =>
                [
                    "../openssl/crypto/x509v3/v3_extku.c",
                ],
            "crypto/x509v3/v3_genn.o" =>
                [
                    "../openssl/crypto/x509v3/v3_genn.c",
                ],
            "crypto/x509v3/v3_ia5.o" =>
                [
                    "../openssl/crypto/x509v3/v3_ia5.c",
                ],
            "crypto/x509v3/v3_info.o" =>
                [
                    "../openssl/crypto/x509v3/v3_info.c",
                ],
            "crypto/x509v3/v3_int.o" =>
                [
                    "../openssl/crypto/x509v3/v3_int.c",
                ],
            "crypto/x509v3/v3_lib.o" =>
                [
                    "../openssl/crypto/x509v3/v3_lib.c",
                ],
            "crypto/x509v3/v3_ncons.o" =>
                [
                    "../openssl/crypto/x509v3/v3_ncons.c",
                ],
            "crypto/x509v3/v3_pci.o" =>
                [
                    "../openssl/crypto/x509v3/v3_pci.c",
                ],
            "crypto/x509v3/v3_pcia.o" =>
                [
                    "../openssl/crypto/x509v3/v3_pcia.c",
                ],
            "crypto/x509v3/v3_pcons.o" =>
                [
                    "../openssl/crypto/x509v3/v3_pcons.c",
                ],
            "crypto/x509v3/v3_pku.o" =>
                [
                    "../openssl/crypto/x509v3/v3_pku.c",
                ],
            "crypto/x509v3/v3_pmaps.o" =>
                [
                    "../openssl/crypto/x509v3/v3_pmaps.c",
                ],
            "crypto/x509v3/v3_prn.o" =>
                [
                    "../openssl/crypto/x509v3/v3_prn.c",
                ],
            "crypto/x509v3/v3_purp.o" =>
                [
                    "../openssl/crypto/x509v3/v3_purp.c",
                ],
            "crypto/x509v3/v3_skey.o" =>
                [
                    "../openssl/crypto/x509v3/v3_skey.c",
                ],
            "crypto/x509v3/v3_sxnet.o" =>
                [
                    "../openssl/crypto/x509v3/v3_sxnet.c",
                ],
            "crypto/x509v3/v3_tlsf.o" =>
                [
                    "../openssl/crypto/x509v3/v3_tlsf.c",
                ],
            "crypto/x509v3/v3_utl.o" =>
                [
                    "../openssl/crypto/x509v3/v3_utl.c",
                ],
            "crypto/x509v3/v3err.o" =>
                [
                    "../openssl/crypto/x509v3/v3err.c",
                ],
            "libcrypto" =>
                [
                    "crypto/aes/aes_cbc.o",
                    "crypto/aes/aes_cfb.o",
                    "crypto/aes/aes_core.o",
                    "crypto/aes/aes_ecb.o",
                    "crypto/aes/aes_ige.o",
                    "crypto/aes/aes_misc.o",
                    "crypto/aes/aes_ofb.o",
                    "crypto/aes/aes_wrap.o",
                    "crypto/asn1/a_bitstr.o",
                    "crypto/asn1/a_d2i_fp.o",
                    "crypto/asn1/a_digest.o",
                    "crypto/asn1/a_dup.o",
                    "crypto/asn1/a_gentm.o",
                    "crypto/asn1/a_i2d_fp.o",
                    "crypto/asn1/a_int.o",
                    "crypto/asn1/a_mbstr.o",
                    "crypto/asn1/a_object.o",
                    "crypto/asn1/a_octet.o",
                    "crypto/asn1/a_print.o",
                    "crypto/asn1/a_sign.o",
                    "crypto/asn1/a_strex.o",
                    "crypto/asn1/a_strnid.o",
                    "crypto/asn1/a_time.o",
                    "crypto/asn1/a_type.o",
                    "crypto/asn1/a_utctm.o",
                    "crypto/asn1/a_utf8.o",
                    "crypto/asn1/a_verify.o",
                    "crypto/asn1/ameth_lib.o",
                    "crypto/asn1/asn1_err.o",
                    "crypto/asn1/asn1_gen.o",
                    "crypto/asn1/asn1_item_list.o",
                    "crypto/asn1/asn1_lib.o",
                    "crypto/asn1/asn1_par.o",
                    "crypto/asn1/asn_mime.o",
                    "crypto/asn1/asn_moid.o",
                    "crypto/asn1/asn_mstbl.o",
                    "crypto/asn1/asn_pack.o",
                    "crypto/asn1/bio_asn1.o",
                    "crypto/asn1/bio_ndef.o",
                    "crypto/asn1/d2i_pr.o",
                    "crypto/asn1/d2i_pu.o",
                    "crypto/asn1/evp_asn1.o",
                    "crypto/asn1/f_int.o",
                    "crypto/asn1/f_string.o",
                    "crypto/asn1/i2d_pr.o",
                    "crypto/asn1/i2d_pu.o",
                    "crypto/asn1/n_pkey.o",
                    "crypto/asn1/nsseq.o",
                    "crypto/asn1/p5_pbe.o",
                    "crypto/asn1/p5_pbev2.o",
                    "crypto/asn1/p5_scrypt.o",
                    "crypto/asn1/p8_pkey.o",
                    "crypto/asn1/t_bitst.o",
                    "crypto/asn1/t_pkey.o",
                    "crypto/asn1/t_spki.o",
                    "crypto/asn1/tasn_dec.o",
                    "crypto/asn1/tasn_enc.o",
                    "crypto/asn1/tasn_fre.o",
                    "crypto/asn1/tasn_new.o",
                    "crypto/asn1/tasn_prn.o",
                    "crypto/asn1/tasn_scn.o",
                    "crypto/asn1/tasn_typ.o",
                    "crypto/asn1/tasn_utl.o",
                    "crypto/asn1/x_algor.o",
                    "crypto/asn1/x_bignum.o",
                    "crypto/asn1/x_info.o",
                    "crypto/asn1/x_int64.o",
                    "crypto/asn1/x_long.o",
                    "crypto/asn1/x_pkey.o",
                    "crypto/asn1/x_sig.o",
                    "crypto/asn1/x_spki.o",
                    "crypto/asn1/x_val.o",
                    "crypto/async/arch/async_null.o",
                    "crypto/async/arch/async_posix.o",
                    "crypto/async/arch/async_win.o",
                    "crypto/async/async.o",
                    "crypto/async/async_err.o",
                    "crypto/async/async_wait.o",
                    "crypto/bio/b_addr.o",
                    "crypto/bio/b_dump.o",
                    "crypto/bio/b_print.o",
                    "crypto/bio/b_sock.o",
                    "crypto/bio/b_sock2.o",
                    "crypto/bio/bf_buff.o",
                    "crypto/bio/bf_lbuf.o",
                    "crypto/bio/bf_nbio.o",
                    "crypto/bio/bf_null.o",
                    "crypto/bio/bio_cb.o",
                    "crypto/bio/bio_err.o",
                    "crypto/bio/bio_lib.o",
                    "crypto/bio/bio_meth.o",
                    "crypto/bio/bss_acpt.o",
                    "crypto/bio/bss_bio.o",
                    "crypto/bio/bss_conn.o",
                    "crypto/bio/bss_dgram.o",
                    "crypto/bio/bss_fd.o",
                    "crypto/bio/bss_file.o",
                    "crypto/bio/bss_log.o",
                    "crypto/bio/bss_mem.o",
                    "crypto/bio/bss_null.o",
                    "crypto/bio/bss_sock.o",
                    "crypto/bn/bn_add.o",
                    "crypto/bn/bn_asm.o",
                    "crypto/bn/bn_blind.o",
                    "crypto/bn/bn_const.o",
                    "crypto/bn/bn_ctx.o",
                    "crypto/bn/bn_depr.o",
                    "crypto/bn/bn_dh.o",
                    "crypto/bn/bn_div.o",
                    "crypto/bn/bn_err.o",
                    "crypto/bn/bn_exp.o",
                    "crypto/bn/bn_exp2.o",
                    "crypto/bn/bn_gcd.o",
                    "crypto/bn/bn_gf2m.o",
                    "crypto/bn/bn_intern.o",
                    "crypto/bn/bn_kron.o",
                    "crypto/bn/bn_lib.o",
                    "crypto/bn/bn_mod.o",
                    "crypto/bn/bn_mont.o",
                    "crypto/bn/bn_mpi.o",
                    "crypto/bn/bn_mul.o",
                    "crypto/bn/bn_nist.o",
                    "crypto/bn/bn_prime.o",
                    "crypto/bn/bn_print.o",
                    "crypto/bn/bn_rand.o",
                    "crypto/bn/bn_recp.o",
                    "crypto/bn/bn_shift.o",
                    "crypto/bn/bn_sqr.o",
                    "crypto/bn/bn_sqrt.o",
                    "crypto/bn/bn_srp.o",
                    "crypto/bn/bn_word.o",
                    "crypto/bn/bn_x931p.o",
                    "crypto/buffer/buf_err.o",
                    "crypto/buffer/buffer.o",
                    "crypto/camellia/camellia.o",
                    "crypto/camellia/cmll_cbc.o",
                    "crypto/camellia/cmll_cfb.o",
                    "crypto/camellia/cmll_ctr.o",
                    "crypto/camellia/cmll_ecb.o",
                    "crypto/camellia/cmll_misc.o",
                    "crypto/camellia/cmll_ofb.o",
                    "crypto/cmac/cm_ameth.o",
                    "crypto/cmac/cm_pmeth.o",
                    "crypto/cmac/cmac.o",
                    "crypto/conf/conf_api.o",
                    "crypto/conf/conf_def.o",
                    "crypto/conf/conf_err.o",
                    "crypto/conf/conf_lib.o",
                    "crypto/conf/conf_mall.o",
                    "crypto/conf/conf_mod.o",
                    "crypto/conf/conf_sap.o",
                    "crypto/conf/conf_ssl.o",
                    "crypto/cpt_err.o",
                    "crypto/cryptlib.o",
                    "crypto/ctype.o",
                    "crypto/cversion.o",
                    "crypto/des/cbc_cksm.o",
                    "crypto/des/cbc_enc.o",
                    "crypto/des/cfb64ede.o",
                    "crypto/des/cfb64enc.o",
                    "crypto/des/cfb_enc.o",
                    "crypto/des/des_enc.o",
                    "crypto/des/ecb3_enc.o",
                    "crypto/des/ecb_enc.o",
                    "crypto/des/fcrypt.o",
                    "crypto/des/fcrypt_b.o",
                    "crypto/des/ofb64ede.o",
                    "crypto/des/ofb64enc.o",
                    "crypto/des/ofb_enc.o",
                    "crypto/des/pcbc_enc.o",
                    "crypto/des/qud_cksm.o",
                    "crypto/des/rand_key.o",
                    "crypto/des/set_key.o",
                    "crypto/des/str2key.o",
                    "crypto/des/xcbc_enc.o",
                    "crypto/dh/dh_ameth.o",
                    "crypto/dh/dh_asn1.o",
                    "crypto/dh/dh_check.o",
                    "crypto/dh/dh_depr.o",
                    "crypto/dh/dh_err.o",
                    "crypto/dh/dh_gen.o",
                    "crypto/dh/dh_kdf.o",
                    "crypto/dh/dh_key.o",
                    "crypto/dh/dh_lib.o",
                    "crypto/dh/dh_meth.o",
                    "crypto/dh/dh_pmeth.o",
                    "crypto/dh/dh_prn.o",
                    "crypto/dh/dh_rfc5114.o",
                    "crypto/dh/dh_rfc7919.o",
                    "crypto/dso/dso_dl.o",
                    "crypto/dso/dso_dlfcn.o",
                    "crypto/dso/dso_err.o",
                    "crypto/dso/dso_lib.o",
                    "crypto/dso/dso_openssl.o",
                    "crypto/dso/dso_vms.o",
                    "crypto/dso/dso_win32.o",
                    "crypto/ebcdic.o",
                    "crypto/ec/curve25519.o",
                    "crypto/ec/curve448/arch_32/f_impl.o",
                    "crypto/ec/curve448/curve448.o",
                    "crypto/ec/curve448/curve448_tables.o",
                    "crypto/ec/curve448/eddsa.o",
                    "crypto/ec/curve448/f_generic.o",
                    "crypto/ec/curve448/scalar.o",
                    "crypto/ec/ec2_oct.o",
                    "crypto/ec/ec2_smpl.o",
                    "crypto/ec/ec_ameth.o",
                    "crypto/ec/ec_asn1.o",
                    "crypto/ec/ec_check.o",
                    "crypto/ec/ec_curve.o",
                    "crypto/ec/ec_cvt.o",
                    "crypto/ec/ec_err.o",
                    "crypto/ec/ec_key.o",
                    "crypto/ec/ec_kmeth.o",
                    "crypto/ec/ec_lib.o",
                    "crypto/ec/ec_mult.o",
                    "crypto/ec/ec_oct.o",
                    "crypto/ec/ec_pmeth.o",
                    "crypto/ec/ec_print.o",
                    "crypto/ec/ecdh_kdf.o",
                    "crypto/ec/ecdh_ossl.o",
                    "crypto/ec/ecdsa_ossl.o",
                    "crypto/ec/ecdsa_sign.o",
                    "crypto/ec/ecdsa_vrf.o",
                    "crypto/ec/eck_prn.o",
                    "crypto/ec/ecp_mont.o",
                    "crypto/ec/ecp_nist.o",
                    "crypto/ec/ecp_nistp224.o",
                    "crypto/ec/ecp_nistp256.o",
                    "crypto/ec/ecp_nistp521.o",
                    "crypto/ec/ecp_nistputil.o",
                    "crypto/ec/ecp_oct.o",
                    "crypto/ec/ecp_smpl.o",
                    "crypto/ec/ecx_meth.o",
                    "crypto/err/err.o",
                    "crypto/err/err_all.o",
                    "crypto/err/err_prn.o",
                    "crypto/evp/bio_b64.o",
                    "crypto/evp/bio_enc.o",
                    "crypto/evp/bio_md.o",
                    "crypto/evp/bio_ok.o",
                    "crypto/evp/c_allc.o",
                    "crypto/evp/c_alld.o",
                    "crypto/evp/cmeth_lib.o",
                    "crypto/evp/digest.o",
                    "crypto/evp/e_aes.o",
                    "crypto/evp/e_aes_cbc_hmac_sha1.o",
                    "crypto/evp/e_aes_cbc_hmac_sha256.o",
                    "crypto/evp/e_aria.o",
                    "crypto/evp/e_bf.o",
                    "crypto/evp/e_camellia.o",
                    "crypto/evp/e_cast.o",
                    "crypto/evp/e_chacha20_poly1305.o",
                    "crypto/evp/e_des.o",
                    "crypto/evp/e_des3.o",
                    "crypto/evp/e_idea.o",
                    "crypto/evp/e_null.o",
                    "crypto/evp/e_old.o",
                    "crypto/evp/e_rc2.o",
                    "crypto/evp/e_rc4.o",
                    "crypto/evp/e_rc4_hmac_md5.o",
                    "crypto/evp/e_rc5.o",
                    "crypto/evp/e_seed.o",
                    "crypto/evp/e_sm4.o",
                    "crypto/evp/e_xcbc_d.o",
                    "crypto/evp/encode.o",
                    "crypto/evp/evp_cnf.o",
                    "crypto/evp/evp_enc.o",
                    "crypto/evp/evp_err.o",
                    "crypto/evp/evp_key.o",
                    "crypto/evp/evp_lib.o",
                    "crypto/evp/evp_pbe.o",
                    "crypto/evp/evp_pkey.o",
                    "crypto/evp/m_md2.o",
                    "crypto/evp/m_md4.o",
                    "crypto/evp/m_md5.o",
                    "crypto/evp/m_md5_sha1.o",
                    "crypto/evp/m_mdc2.o",
                    "crypto/evp/m_null.o",
                    "crypto/evp/m_ripemd.o",
                    "crypto/evp/m_sha1.o",
                    "crypto/evp/m_sha3.o",
                    "crypto/evp/m_sigver.o",
                    "crypto/evp/m_wp.o",
                    "crypto/evp/names.o",
                    "crypto/evp/p5_crpt.o",
                    "crypto/evp/p5_crpt2.o",
                    "crypto/evp/p_dec.o",
                    "crypto/evp/p_enc.o",
                    "crypto/evp/p_lib.o",
                    "crypto/evp/p_open.o",
                    "crypto/evp/p_seal.o",
                    "crypto/evp/p_sign.o",
                    "crypto/evp/p_verify.o",
                    "crypto/evp/pbe_scrypt.o",
                    "crypto/evp/pmeth_fn.o",
                    "crypto/evp/pmeth_gn.o",
                    "crypto/evp/pmeth_lib.o",
                    "crypto/ex_data.o",
                    "crypto/getenv.o",
                    "crypto/hmac/hm_ameth.o",
                    "crypto/hmac/hm_pmeth.o",
                    "crypto/hmac/hmac.o",
                    "crypto/init.o",
                    "crypto/kdf/hkdf.o",
                    "crypto/kdf/kdf_err.o",
                    "crypto/kdf/scrypt.o",
                    "crypto/kdf/tls1_prf.o",
                    "crypto/lhash/lh_stats.o",
                    "crypto/lhash/lhash.o",
                    "crypto/md5/md5_dgst.o",
                    "crypto/md5/md5_one.o",
                    "crypto/mem.o",
                    "crypto/mem_clr.o",
                    "crypto/mem_dbg.o",
                    "crypto/mem_sec.o",
                    "crypto/modes/cbc128.o",
                    "crypto/modes/ccm128.o",
                    "crypto/modes/cfb128.o",
                    "crypto/modes/ctr128.o",
                    "crypto/modes/cts128.o",
                    "crypto/modes/gcm128.o",
                    "crypto/modes/ocb128.o",
                    "crypto/modes/ofb128.o",
                    "crypto/modes/wrap128.o",
                    "crypto/modes/xts128.o",
                    "crypto/o_dir.o",
                    "crypto/o_fips.o",
                    "crypto/o_fopen.o",
                    "crypto/o_init.o",
                    "crypto/o_str.o",
                    "crypto/o_time.o",
                    "crypto/objects/o_names.o",
                    "crypto/objects/obj_dat.o",
                    "crypto/objects/obj_err.o",
                    "crypto/objects/obj_lib.o",
                    "crypto/objects/obj_xref.o",
                    "crypto/pem/pem_all.o",
                    "crypto/pem/pem_err.o",
                    "crypto/pem/pem_info.o",
                    "crypto/pem/pem_lib.o",
                    "crypto/pem/pem_oth.o",
                    "crypto/pem/pem_pk8.o",
                    "crypto/pem/pem_pkey.o",
                    "crypto/pem/pem_sign.o",
                    "crypto/pem/pem_x509.o",
                    "crypto/pem/pem_xaux.o",
                    "crypto/pem/pvkfmt.o",
                    "crypto/pkcs12/p12_add.o",
                    "crypto/pkcs12/p12_asn.o",
                    "crypto/pkcs12/p12_attr.o",
                    "crypto/pkcs12/p12_crpt.o",
                    "crypto/pkcs12/p12_crt.o",
                    "crypto/pkcs12/p12_decr.o",
                    "crypto/pkcs12/p12_init.o",
                    "crypto/pkcs12/p12_key.o",
                    "crypto/pkcs12/p12_kiss.o",
                    "crypto/pkcs12/p12_mutl.o",
                    "crypto/pkcs12/p12_npas.o",
                    "crypto/pkcs12/p12_p8d.o",
                    "crypto/pkcs12/p12_p8e.o",
                    "crypto/pkcs12/p12_sbag.o",
                    "crypto/pkcs12/p12_utl.o",
                    "crypto/pkcs12/pk12err.o",
                    "crypto/pkcs7/bio_pk7.o",
                    "crypto/pkcs7/pk7_asn1.o",
                    "crypto/pkcs7/pk7_attr.o",
                    "crypto/pkcs7/pk7_doit.o",
                    "crypto/pkcs7/pk7_lib.o",
                    "crypto/pkcs7/pk7_mime.o",
                    "crypto/pkcs7/pk7_smime.o",
                    "crypto/pkcs7/pkcs7err.o",
                    "crypto/rand/drbg_ctr.o",
                    "crypto/rand/drbg_lib.o",
                    "crypto/rand/rand_egd.o",
                    "crypto/rand/rand_err.o",
                    "crypto/rand/rand_lib.o",
                    "crypto/rand/rand_unix.o",
                    "crypto/rand/rand_vms.o",
                    "crypto/rand/rand_win.o",
                    "crypto/rand/randfile.o",
                    "crypto/rc4/rc4_enc.o",
                    "crypto/rc4/rc4_skey.o",
                    "crypto/rsa/rsa_ameth.o",
                    "crypto/rsa/rsa_asn1.o",
                    "crypto/rsa/rsa_chk.o",
                    "crypto/rsa/rsa_crpt.o",
                    "crypto/rsa/rsa_depr.o",
                    "crypto/rsa/rsa_err.o",
                    "crypto/rsa/rsa_gen.o",
                    "crypto/rsa/rsa_lib.o",
                    "crypto/rsa/rsa_meth.o",
                    "crypto/rsa/rsa_mp.o",
                    "crypto/rsa/rsa_none.o",
                    "crypto/rsa/rsa_oaep.o",
                    "crypto/rsa/rsa_ossl.o",
                    "crypto/rsa/rsa_pk1.o",
                    "crypto/rsa/rsa_pmeth.o",
                    "crypto/rsa/rsa_prn.o",
                    "crypto/rsa/rsa_pss.o",
                    "crypto/rsa/rsa_saos.o",
                    "crypto/rsa/rsa_sign.o",
                    "crypto/rsa/rsa_ssl.o",
                    "crypto/rsa/rsa_x931.o",
                    "crypto/rsa/rsa_x931g.o",
                    "crypto/sha/keccak1600.o",
                    "crypto/sha/sha1_one.o",
                    "crypto/sha/sha1dgst.o",
                    "crypto/sha/sha256.o",
                    "crypto/sha/sha512.o",
                    "crypto/siphash/siphash.o",
                    "crypto/siphash/siphash_ameth.o",
                    "crypto/siphash/siphash_pmeth.o",
                    "crypto/sm2/sm2_crypt.o",
                    "crypto/sm2/sm2_err.o",
                    "crypto/sm2/sm2_pmeth.o",
                    "crypto/sm2/sm2_sign.o",
                    "crypto/sm3/m_sm3.o",
                    "crypto/sm3/sm3.o",
                    "crypto/sm4/sm4.o",
                    "crypto/stack/stack.o",
                    "crypto/store/loader_file.o",
                    "crypto/store/store_err.o",
                    "crypto/store/store_init.o",
                    "crypto/store/store_lib.o",
                    "crypto/store/store_register.o",
                    "crypto/store/store_strings.o",
                    "crypto/threads_none.o",
                    "crypto/threads_pthread.o",
                    "crypto/threads_win.o",
                    "crypto/txt_db/txt_db.o",
                    "crypto/ui/ui_err.o",
                    "crypto/ui/ui_lib.o",
                    "crypto/ui/ui_null.o",
                    "crypto/ui/ui_openssl.o",
                    "crypto/ui/ui_util.o",
                    "crypto/uid.o",
                    "crypto/x509/by_dir.o",
                    "crypto/x509/by_file.o",
                    "crypto/x509/t_crl.o",
                    "crypto/x509/t_req.o",
                    "crypto/x509/t_x509.o",
                    "crypto/x509/x509_att.o",
                    "crypto/x509/x509_cmp.o",
                    "crypto/x509/x509_d2.o",
                    "crypto/x509/x509_def.o",
                    "crypto/x509/x509_err.o",
                    "crypto/x509/x509_ext.o",
                    "crypto/x509/x509_lu.o",
                    "crypto/x509/x509_meth.o",
                    "crypto/x509/x509_obj.o",
                    "crypto/x509/x509_r2x.o",
                    "crypto/x509/x509_req.o",
                    "crypto/x509/x509_set.o",
                    "crypto/x509/x509_trs.o",
                    "crypto/x509/x509_txt.o",
                    "crypto/x509/x509_v3.o",
                    "crypto/x509/x509_vfy.o",
                    "crypto/x509/x509_vpm.o",
                    "crypto/x509/x509cset.o",
                    "crypto/x509/x509name.o",
                    "crypto/x509/x509rset.o",
                    "crypto/x509/x509spki.o",
                    "crypto/x509/x509type.o",
                    "crypto/x509/x_all.o",
                    "crypto/x509/x_attrib.o",
                    "crypto/x509/x_crl.o",
                    "crypto/x509/x_exten.o",
                    "crypto/x509/x_name.o",
                    "crypto/x509/x_pubkey.o",
                    "crypto/x509/x_req.o",
                    "crypto/x509/x_x509.o",
                    "crypto/x509/x_x509a.o",
                    "crypto/x509v3/pcy_cache.o",
                    "crypto/x509v3/pcy_data.o",
                    "crypto/x509v3/pcy_lib.o",
                    "crypto/x509v3/pcy_map.o",
                    "crypto/x509v3/pcy_node.o",
                    "crypto/x509v3/pcy_tree.o",
                    "crypto/x509v3/v3_addr.o",
                    "crypto/x509v3/v3_admis.o",
                    "crypto/x509v3/v3_akey.o",
                    "crypto/x509v3/v3_akeya.o",
                    "crypto/x509v3/v3_alt.o",
                    "crypto/x509v3/v3_asid.o",
                    "crypto/x509v3/v3_bcons.o",
                    "crypto/x509v3/v3_bitst.o",
                    "crypto/x509v3/v3_conf.o",
                    "crypto/x509v3/v3_cpols.o",
                    "crypto/x509v3/v3_crld.o",
                    "crypto/x509v3/v3_enum.o",
                    "crypto/x509v3/v3_extku.o",
                    "crypto/x509v3/v3_genn.o",
                    "crypto/x509v3/v3_ia5.o",
                    "crypto/x509v3/v3_info.o",
                    "crypto/x509v3/v3_int.o",
                    "crypto/x509v3/v3_lib.o",
                    "crypto/x509v3/v3_ncons.o",
                    "crypto/x509v3/v3_pci.o",
                    "crypto/x509v3/v3_pcia.o",
                    "crypto/x509v3/v3_pcons.o",
                    "crypto/x509v3/v3_pku.o",
                    "crypto/x509v3/v3_pmaps.o",
                    "crypto/x509v3/v3_prn.o",
                    "crypto/x509v3/v3_purp.o",
                    "crypto/x509v3/v3_skey.o",
                    "crypto/x509v3/v3_sxnet.o",
                    "crypto/x509v3/v3_tlsf.o",
                    "crypto/x509v3/v3_utl.o",
                    "crypto/x509v3/v3err.o",
                ],
            "libssl" =>
                [
                    "ssl/bio_ssl.o",
                    "ssl/d1_lib.o",
                    "ssl/d1_msg.o",
                    "ssl/d1_srtp.o",
                    "ssl/methods.o",
                    "ssl/packet.o",
                    "ssl/pqueue.o",
                    "ssl/record/dtls1_bitmap.o",
                    "ssl/record/rec_layer_d1.o",
                    "ssl/record/rec_layer_s3.o",
                    "ssl/record/ssl3_buffer.o",
                    "ssl/record/ssl3_record.o",
                    "ssl/record/ssl3_record_tls13.o",
                    "ssl/s3_cbc.o",
                    "ssl/s3_enc.o",
                    "ssl/s3_lib.o",
                    "ssl/s3_msg.o",
                    "ssl/ssl_asn1.o",
                    "ssl/ssl_cert.o",
                    "ssl/ssl_ciph.o",
                    "ssl/ssl_conf.o",
                    "ssl/ssl_err.o",
                    "ssl/ssl_init.o",
                    "ssl/ssl_lib.o",
                    "ssl/ssl_mcnf.o",
                    "ssl/ssl_rsa.o",
                    "ssl/ssl_sess.o",
                    "ssl/ssl_stat.o",
                    "ssl/ssl_txt.o",
                    "ssl/ssl_utst.o",
                    "ssl/statem/extensions.o",
                    "ssl/statem/extensions_clnt.o",
                    "ssl/statem/extensions_cust.o",
                    "ssl/statem/extensions_srvr.o",
                    "ssl/statem/statem.o",
                    "ssl/statem/statem_clnt.o",
                    "ssl/statem/statem_dtls.o",
                    "ssl/statem/statem_lib.o",
                    "ssl/statem/statem_srvr.o",
                    "ssl/t1_enc.o",
                    "ssl/t1_lib.o",
                    "ssl/t1_trce.o",
                    "ssl/tls13_enc.o",
                    "ssl/tls_srp.o",
                ],
            "ssl/bio_ssl.o" =>
                [
                    "../openssl/ssl/bio_ssl.c",
                ],
            "ssl/d1_lib.o" =>
                [
                    "../openssl/ssl/d1_lib.c",
                ],
            "ssl/d1_msg.o" =>
                [
                    "../openssl/ssl/d1_msg.c",
                ],
            "ssl/d1_srtp.o" =>
                [
                    "../openssl/ssl/d1_srtp.c",
                ],
            "ssl/methods.o" =>
                [
                    "../openssl/ssl/methods.c",
                ],
            "ssl/packet.o" =>
                [
                    "../openssl/ssl/packet.c",
                ],
            "ssl/pqueue.o" =>
                [
                    "../openssl/ssl/pqueue.c",
                ],
            "ssl/record/dtls1_bitmap.o" =>
                [
                    "../openssl/ssl/record/dtls1_bitmap.c",
                ],
            "ssl/record/rec_layer_d1.o" =>
                [
                    "../openssl/ssl/record/rec_layer_d1.c",
                ],
            "ssl/record/rec_layer_s3.o" =>
                [
                    "../openssl/ssl/record/rec_layer_s3.c",
                ],
            "ssl/record/ssl3_buffer.o" =>
                [
                    "../openssl/ssl/record/ssl3_buffer.c",
                ],
            "ssl/record/ssl3_record.o" =>
                [
                    "../openssl/ssl/record/ssl3_record.c",
                ],
            "ssl/record/ssl3_record_tls13.o" =>
                [
                    "../openssl/ssl/record/ssl3_record_tls13.c",
                ],
            "ssl/s3_cbc.o" =>
                [
                    "../openssl/ssl/s3_cbc.c",
                ],
            "ssl/s3_enc.o" =>
                [
                    "../openssl/ssl/s3_enc.c",
                ],
            "ssl/s3_lib.o" =>
                [
                    "../openssl/ssl/s3_lib.c",
                ],
            "ssl/s3_msg.o" =>
                [
                    "../openssl/ssl/s3_msg.c",
                ],
            "ssl/ssl_asn1.o" =>
                [
                    "../openssl/ssl/ssl_asn1.c",
                ],
            "ssl/ssl_cert.o" =>
                [
                    "../openssl/ssl/ssl_cert.c",
                ],
            "ssl/ssl_ciph.o" =>
                [
                    "../openssl/ssl/ssl_ciph.c",
                ],
            "ssl/ssl_conf.o" =>
                [
                    "../openssl/ssl/ssl_conf.c",
                ],
            "ssl/ssl_err.o" =>
                [
                    "../openssl/ssl/ssl_err.c",
                ],
            "ssl/ssl_init.o" =>
                [
                    "../openssl/ssl/ssl_init.c",
                ],
            "ssl/ssl_lib.o" =>
                [
                    "../openssl/ssl/ssl_lib.c",
                ],
            "ssl/ssl_mcnf.o" =>
                [
                    "../openssl/ssl/ssl_mcnf.c",
                ],
            "ssl/ssl_rsa.o" =>
                [
                    "../openssl/ssl/ssl_rsa.c",
                ],
            "ssl/ssl_sess.o" =>
                [
                    "../openssl/ssl/ssl_sess.c",
                ],
            "ssl/ssl_stat.o" =>
                [
                    "../openssl/ssl/ssl_stat.c",
                ],
            "ssl/ssl_txt.o" =>
                [
                    "../openssl/ssl/ssl_txt.c",
                ],
            "ssl/ssl_utst.o" =>
                [
                    "../openssl/ssl/ssl_utst.c",
                ],
            "ssl/statem/extensions.o" =>
                [
                    "../openssl/ssl/statem/extensions.c",
                ],
            "ssl/statem/extensions_clnt.o" =>
                [
                    "../openssl/ssl/statem/extensions_clnt.c",
                ],
            "ssl/statem/extensions_cust.o" =>
                [
                    "../openssl/ssl/statem/extensions_cust.c",
                ],
            "ssl/statem/extensions_srvr.o" =>
                [
                    "../openssl/ssl/statem/extensions_srvr.c",
                ],
            "ssl/statem/statem.o" =>
                [
                    "../openssl/ssl/statem/statem.c",
                ],
            "ssl/statem/statem_clnt.o" =>
                [
                    "../openssl/ssl/statem/statem_clnt.c",
                ],
            "ssl/statem/statem_dtls.o" =>
                [
                    "../openssl/ssl/statem/statem_dtls.c",
                ],
            "ssl/statem/statem_lib.o" =>
                [
                    "../openssl/ssl/statem/statem_lib.c",
                ],
            "ssl/statem/statem_srvr.o" =>
                [
                    "../openssl/ssl/statem/statem_srvr.c",
                ],
            "ssl/t1_enc.o" =>
                [
                    "../openssl/ssl/t1_enc.c",
                ],
            "ssl/t1_lib.o" =>
                [
                    "../openssl/ssl/t1_lib.c",
                ],
            "ssl/t1_trce.o" =>
                [
                    "../openssl/ssl/t1_trce.c",
                ],
            "ssl/tls13_enc.o" =>
                [
                    "../openssl/ssl/tls13_enc.c",
                ],
            "ssl/tls_srp.o" =>
                [
                    "../openssl/ssl/tls_srp.c",
                ],
            "util/shlib_wrap.sh" =>
                [
                    "../openssl/util/shlib_wrap.sh.in",
                ],
        },
);

# The following data is only used when this files is use as a script
my @makevars = (
    'AR',
    'ARFLAGS',
    'AS',
    'ASFLAGS',
    'CC',
    'CFLAGS',
    'CPP',
    'CPPDEFINES',
    'CPPFLAGS',
    'CPPINCLUDES',
    'CROSS_COMPILE',
    'CXX',
    'CXXFLAGS',
    'HASHBANGPERL',
    'LD',
    'LDFLAGS',
    'LDLIBS',
    'MT',
    'MTFLAGS',
    'PERL',
    'RANLIB',
    'RC',
    'RCFLAGS',
    'RM',
);
my %disabled_info = (
    'afalgeng' => {
        macro => 'OPENSSL_NO_AFALGENG',
    },
    'apps' => {
        macro => 'OPENSSL_NO_APPS',
    },
    'aria' => {
        macro => 'OPENSSL_NO_ARIA',
        skipped => [ 'crypto/aria' ],
    },
    'asan' => {
        macro => 'OPENSSL_NO_ASAN',
    },
    'asm' => {
        macro => 'OPENSSL_NO_ASM',
    },
    'async' => {
        macro => 'OPENSSL_NO_ASYNC',
    },
    'autoalginit' => {
        macro => 'OPENSSL_NO_AUTOALGINIT',
    },
    'autoerrinit' => {
        macro => 'OPENSSL_NO_AUTOERRINIT',
    },
    'autoload-config' => {
        macro => 'OPENSSL_NO_AUTOLOAD_CONFIG',
    },
    'bf' => {
        macro => 'OPENSSL_NO_BF',
        skipped => [ 'crypto/bf' ],
    },
    'blake2' => {
        macro => 'OPENSSL_NO_BLAKE2',
        skipped => [ 'crypto/blake2' ],
    },
    'capieng' => {
        macro => 'OPENSSL_NO_CAPIENG',
    },
    'cast' => {
        macro => 'OPENSSL_NO_CAST',
        skipped => [ 'crypto/cast' ],
    },
    'chacha' => {
        macro => 'OPENSSL_NO_CHACHA',
        skipped => [ 'crypto/chacha' ],
    },
    'cms' => {
        macro => 'OPENSSL_NO_CMS',
        skipped => [ 'crypto/cms' ],
    },
    'comp' => {
        macro => 'OPENSSL_NO_COMP',
        skipped => [ 'crypto/comp' ],
    },
    'crypto-mdebug' => {
        macro => 'OPENSSL_NO_CRYPTO_MDEBUG',
    },
    'crypto-mdebug-backtrace' => {
        macro => 'OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE',
    },
    'ct' => {
        macro => 'OPENSSL_NO_CT',
        skipped => [ 'crypto/ct' ],
    },
    'deprecated' => {
        macro => 'OPENSSL_NO_DEPRECATED',
    },
    'devcryptoeng' => {
        macro => 'OPENSSL_NO_DEVCRYPTOENG',
    },
    'dgram' => {
        macro => 'OPENSSL_NO_DGRAM',
    },
    'dsa' => {
        macro => 'OPENSSL_NO_DSA',
        skipped => [ 'crypto/dsa' ],
    },
    'dso' => {
        macro => 'OPENSSL_NO_DSO',
    },
    'dtls' => {
        macro => 'OPENSSL_NO_DTLS',
    },
    'dtls1' => {
        macro => 'OPENSSL_NO_DTLS1',
    },
    'dtls1-method' => {
        macro => 'OPENSSL_NO_DTLS1_METHOD',
    },
    'dtls1_2' => {
        macro => 'OPENSSL_NO_DTLS1_2',
    },
    'dtls1_2-method' => {
        macro => 'OPENSSL_NO_DTLS1_2_METHOD',
    },
    'ec_nistp_64_gcc_128' => {
        macro => 'OPENSSL_NO_EC_NISTP_64_GCC_128',
    },
    'egd' => {
        macro => 'OPENSSL_NO_EGD',
    },
    'engine' => {
        macro => 'OPENSSL_NO_ENGINE',
        skipped => [ 'crypto/engine', 'engines' ],
    },
    'err' => {
        macro => 'OPENSSL_NO_ERR',
    },
    'external-tests' => {
        macro => 'OPENSSL_NO_EXTERNAL_TESTS',
    },
    'filenames' => {
        macro => 'OPENSSL_NO_FILENAMES',
    },
    'fuzz-afl' => {
        macro => 'OPENSSL_NO_FUZZ_AFL',
    },
    'fuzz-libfuzzer' => {
        macro => 'OPENSSL_NO_FUZZ_LIBFUZZER',
    },
    'gost' => {
        macro => 'OPENSSL_NO_GOST',
    },
    'heartbeats' => {
        macro => 'OPENSSL_NO_HEARTBEATS',
    },
    'hw' => {
        macro => 'OPENSSL_NO_HW',
    },
    'hw-padlock' => {
        macro => 'OPENSSL_NO_HW_PADLOCK',
    },
    'idea' => {
        macro => 'OPENSSL_NO_IDEA',
        skipped => [ 'crypto/idea' ],
    },
    'md2' => {
        macro => 'OPENSSL_NO_MD2',
        skipped => [ 'crypto/md2' ],
    },
    'md4' => {
        macro => 'OPENSSL_NO_MD4',
        skipped => [ 'crypto/md4' ],
    },
    'mdc2' => {
        macro => 'OPENSSL_NO_MDC2',
        skipped => [ 'crypto/mdc2' ],
    },
    'msan' => {
        macro => 'OPENSSL_NO_MSAN',
    },
    'multiblock' => {
        macro => 'OPENSSL_NO_MULTIBLOCK',
    },
    'ocb' => {
        macro => 'OPENSSL_NO_OCB',
    },
    'ocsp' => {
        macro => 'OPENSSL_NO_OCSP',
        skipped => [ 'crypto/ocsp' ],
    },
    'poly1305' => {
        macro => 'OPENSSL_NO_POLY1305',
        skipped => [ 'crypto/poly1305' ],
    },
    'posix-io' => {
        macro => 'OPENSSL_NO_POSIX_IO',
    },
    'rc2' => {
        macro => 'OPENSSL_NO_RC2',
        skipped => [ 'crypto/rc2' ],
    },
    'rc5' => {
        macro => 'OPENSSL_NO_RC5',
        skipped => [ 'crypto/rc5' ],
    },
    'rdrand' => {
        macro => 'OPENSSL_NO_RDRAND',
    },
    'rfc3779' => {
        macro => 'OPENSSL_NO_RFC3779',
    },
    'ripemd' => {
        macro => 'OPENSSL_NO_RMD160',
        skipped => [ 'crypto/ripemd' ],
    },
    'scrypt' => {
        macro => 'OPENSSL_NO_SCRYPT',
    },
    'sctp' => {
        macro => 'OPENSSL_NO_SCTP',
    },
    'seed' => {
        macro => 'OPENSSL_NO_SEED',
        skipped => [ 'crypto/seed' ],
    },
    'sock' => {
        macro => 'OPENSSL_NO_SOCK',
    },
    'srp' => {
        macro => 'OPENSSL_NO_SRP',
        skipped => [ 'crypto/srp' ],
    },
    'srtp' => {
        macro => 'OPENSSL_NO_SRTP',
    },
    'ssl-trace' => {
        macro => 'OPENSSL_NO_SSL_TRACE',
    },
    'ssl3' => {
        macro => 'OPENSSL_NO_SSL3',
    },
    'ssl3-method' => {
        macro => 'OPENSSL_NO_SSL3_METHOD',
    },
    'stdio' => {
        macro => 'OPENSSL_NO_STDIO',
    },
    'tests' => {
        macro => 'OPENSSL_NO_TESTS',
    },
    'tls' => {
        macro => 'OPENSSL_NO_TLS',
    },
    'tls1' => {
        macro => 'OPENSSL_NO_TLS1',
    },
    'tls1-method' => {
        macro => 'OPENSSL_NO_TLS1_METHOD',
    },
    'tls1_1' => {
        macro => 'OPENSSL_NO_TLS1_1',
    },
    'tls1_1-method' => {
        macro => 'OPENSSL_NO_TLS1_1_METHOD',
    },
    'tls1_2' => {
        macro => 'OPENSSL_NO_TLS1_2',
    },
    'tls1_2-method' => {
        macro => 'OPENSSL_NO_TLS1_2_METHOD',
    },
    'tls1_3' => {
        macro => 'OPENSSL_NO_TLS1_3',
    },
    'ts' => {
        macro => 'OPENSSL_NO_TS',
        skipped => [ 'crypto/ts' ],
    },
    'ubsan' => {
        macro => 'OPENSSL_NO_UBSAN',
    },
    'ui-console' => {
        macro => 'OPENSSL_NO_UI_CONSOLE',
    },
    'unit-test' => {
        macro => 'OPENSSL_NO_UNIT_TEST',
    },
    'weak-ssl-ciphers' => {
        macro => 'OPENSSL_NO_WEAK_SSL_CIPHERS',
    },
    'whrlpool' => {
        macro => 'OPENSSL_NO_WHIRLPOOL',
        skipped => [ 'crypto/whrlpool' ],
    },
);
my @user_crossable = qw( AR AS CC CXX CPP LD MT RANLIB RC );
# If run directly, we can give some answers, and even reconfigure
unless (caller) {
    use Getopt::Long;
    use File::Spec::Functions;
    use File::Basename;
    use Pod::Usage;

    my $here = dirname($0);

    my $dump = undef;
    my $cmdline = undef;
    my $options = undef;
    my $target = undef;
    my $envvars = undef;
    my $makevars = undef;
    my $buildparams = undef;
    my $reconf = undef;
    my $verbose = undef;
    my $help = undef;
    my $man = undef;
    GetOptions('dump|d'                 => \$dump,
               'command-line|c'         => \$cmdline,
               'options|o'              => \$options,
               'target|t'               => \$target,
               'environment|e'          => \$envvars,
               'make-variables|m'       => \$makevars,
               'build-parameters|b'     => \$buildparams,
               'reconfigure|reconf|r'   => \$reconf,
               'verbose|v'              => \$verbose,
               'help'                   => \$help,
               'man'                    => \$man)
        or die "Errors in command line arguments\n";

    unless ($dump || $cmdline || $options || $target || $envvars || $makevars
            || $buildparams || $reconf || $verbose || $help || $man) {
        print STDERR <<"_____";
You must give at least one option.
For more information, do '$0 --help'
_____
        exit(2);
    }

    if ($help) {
        pod2usage(-exitval => 0,
                  -verbose => 1);
    }
    if ($man) {
        pod2usage(-exitval => 0,
                  -verbose => 2);
    }
    if ($dump || $cmdline) {
        print "\nCommand line (with current working directory = $here):\n\n";
        print '    ',join(' ',
                          $config{PERL},
                          catfile($config{sourcedir}, 'Configure'),
                          @{$config{perlargv}}), "\n";
        print "\nPerl information:\n\n";
        print '    ',$config{perl_cmd},"\n";
        print '    ',$config{perl_version},' for ',$config{perl_archname},"\n";
    }
    if ($dump || $options) {
        my $longest = 0;
        my $longest2 = 0;
        foreach my $what (@disablables) {
            $longest = length($what) if $longest < length($what);
            $longest2 = length($disabled{$what})
                if $disabled{$what} && $longest2 < length($disabled{$what});
        }
        print "\nEnabled features:\n\n";
        foreach my $what (@disablables) {
            print "    $what\n"
                unless grep { $_ =~ /^${what}$/ } keys %disabled;
        }
        print "\nDisabled features:\n\n";
        foreach my $what (@disablables) {
            my @what2 = grep { $_ =~ /^${what}$/ } keys %disabled;
            my $what3 = $what2[0];
            if ($what3) {
                print "    $what3", ' ' x ($longest - length($what3) + 1),
                    "[$disabled{$what3}]", ' ' x ($longest2 - length($disabled{$what3}) + 1);
                print $disabled_info{$what3}->{macro}
                    if $disabled_info{$what3}->{macro};
                print ' (skip ',
                    join(', ', @{$disabled_info{$what3}->{skipped}}),
                    ')'
                    if $disabled_info{$what3}->{skipped};
                print "\n";
            }
        }
    }
    if ($dump || $target) {
        print "\nConfig target attributes:\n\n";
        foreach (sort keys %target) {
            next if $_ =~ m|^_| || $_ eq 'template';
            my $quotify = sub {
                map { (my $x = $_) =~ s|([\\\$\@"])|\\$1|g; "\"$x\""} @_;
            };
            print '    ', $_, ' => ';
            if (ref($target{$_}) eq "ARRAY") {
                print '[ ', join(', ', $quotify->(@{$target{$_}})), " ],\n";
            } else {
                print $quotify->($target{$_}), ",\n"
            }
        }
    }
    if ($dump || $envvars) {
        print "\nRecorded environment:\n\n";
        foreach (sort keys %{$config{perlenv}}) {
            print '    ',$_,' = ',($config{perlenv}->{$_} || ''),"\n";
        }
    }
    if ($dump || $makevars) {
        print "\nMakevars:\n\n";
        foreach my $var (@makevars) {
            my $prefix = '';
            $prefix = $config{CROSS_COMPILE}
                if grep { $var eq $_ } @user_crossable;
            $prefix //= '';
            print '    ',$var,' ' x (16 - length $var),'= ',
                (ref $config{$var} eq 'ARRAY'
                 ? join(' ', @{$config{$var}})
                 : $prefix.$config{$var}),
                "\n"
                if defined $config{$var};
        }

        my @buildfile = ($config{builddir}, $config{build_file});
        unshift @buildfile, $here
            unless file_name_is_absolute($config{builddir});
        my $buildfile = canonpath(catdir(@buildfile));
        print <<"_____";

NOTE: These variables only represent the configuration view.  The build file
template may have processed these variables further, please have a look at the
build file for more exact data:
    $buildfile
_____
    }
    if ($dump || $buildparams) {
        my @buildfile = ($config{builddir}, $config{build_file});
        unshift @buildfile, $here
            unless file_name_is_absolute($config{builddir});
        print "\nbuild file:\n\n";
        print "    ", canonpath(catfile(@buildfile)),"\n";

        print "\nbuild file templates:\n\n";
        foreach (@{$config{build_file_templates}}) {
            my @tmpl = ($_);
            unshift @tmpl, $here
                unless file_name_is_absolute($config{sourcedir});
            print '    ',canonpath(catfile(@tmpl)),"\n";
        }
    }
    if ($reconf) {
        if ($verbose) {
            print 'Reconfiguring with: ', join(' ',@{$config{perlargv}}), "\n";
            foreach (sort keys %{$config{perlenv}}) {
                print '    ',$_,' = ',($config{perlenv}->{$_} || ""),"\n";
            }
        }

        chdir $here;
        exec $^X,catfile($config{sourcedir}, 'Configure'),'reconf';
    }
}

1;

__END__

=head1 NAME

configdata.pm - configuration data for OpenSSL builds

=head1 SYNOPSIS

Interactive:

  perl configdata.pm [options]

As data bank module:

  use configdata;

=head1 DESCRIPTION

This module can be used in two modes, interactively and as a module containing
all the data recorded by OpenSSL's Configure script.

When used interactively, simply run it as any perl script, with at least one
option, and you will get the information you ask for.  See L</OPTIONS> below.

When loaded as a module, you get a few databanks with useful information to
perform build related tasks.  The databanks are:

    %config             Configured things.
    %target             The OpenSSL config target with all inheritances
                        resolved.
    %disabled           The features that are disabled.
    @disablables        The list of features that can be disabled.
    %withargs           All data given through --with-THING options.
    %unified_info       All information that was computed from the build.info
                        files.

=head1 OPTIONS

=over 4

=item B<--help>

Print a brief help message and exit.

=item B<--man>

Print the manual page and exit.

=item B<--dump> | B<-d>

Print all relevant configuration data.  This is equivalent to B<--command-line>
B<--options> B<--target> B<--environment> B<--make-variables>
B<--build-parameters>.

=item B<--command-line> | B<-c>

Print the current configuration command line.

=item B<--options> | B<-o>

Print the features, both enabled and disabled, and display defined macro and
skipped directories where applicable.

=item B<--target> | B<-t>

Print the config attributes for this config target.

=item B<--environment> | B<-e>

Print the environment variables and their values at the time of configuration.

=item B<--make-variables> | B<-m>

Print the main make variables generated in the current configuration

=item B<--build-parameters> | B<-b>

Print the build parameters, i.e. build file and build file templates.

=item B<--reconfigure> | B<--reconf> | B<-r>

Redo the configuration.

=item B<--verbose> | B<-v>

Verbose output.

=back

=cut

