#!/bin/sh

SHA256="ALG_NO"
SHA384="ALG_NO"
SHA512="ALG_NO"
BUILD_OPT="build"

function clean() {
    pushd smallc
    make clean
    popd

    pushd openssl-stubs
    make clean
    popd

    pushd tpm
    make clean
    popd

    cargo clean
}

function build() {
    pushd smallc
    CC=clang AR=llvm-ar make
    popd

    pushd openssl-stubs

    [[ ! -d "conf-include/openssl" ]] && mkdir -p conf-include/openssl
    [[ ! -d "conf-include/crypto" ]] && mkdir -p conf-include/crypto

    CC=clang AR=llvm-ar \
        CFLAGS="-Wall -Werror -Wno-format -target x86_64-unknown-none -fPIC \
        -nostdlib -nostdlibinc -ffreestanding -Istd-include -Iconf-include \
        -Iarch/x86_64 -I../openssl-stubs -include CrtLibSupport.h -std=c99" \
        ./process_openssl.pl

    make -j$(nproc) libcrypto.a
    cp libcrypto.a crypto.lib
    popd

    pushd tpm
    CC=clang AR=llvm-ar make ALG_SHA256=${SHA256} ALG_SHA384=${SHA384} ALG_SHA512=${SHA512}
    popd
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -algo)
            # Split the comma-separated list of algorithms
            IFS=',' read -ra algorithms <<< "$2"
            for algorithm in "${algorithms[@]}"; do
                # Set variables based on specified algorithms
                case "$algorithm" in
                    sha256)
                        SHA256="ALG_YES"
                        ;;
                    sha384)
                        SHA384="ALG_YES"
                        ;;
                    sha512)
                        SHA512="ALG_YES"
                        ;;
                    *)
                        echo "Unknown algorithm: $algorithm"
                        ;;
                esac
            done
            shift
            ;;
        -clean)
            BUILD_OPT="clean"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            ;;
    esac
    shift
done

case "${BUILD_OPT}" in
    clean) clean ;;
    build) build ;;
    *) echo "unknown build option - ${BUILD_OPT}" ;;
esac
