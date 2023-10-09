# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

#!/bin/bash

ALGO="sha256,sha384"
BUILD_OPT="build"
ENABLE_BENCHMARK=0
REMOTE_ATTESTATION="on"

usage() {
   echo "$0 [options]"
   echo "Available <commands>:"
   echo " -algo [sha256,sha384,sha512] Supported hash algorithm. (Default supported algorithms are sha256 and sha384)"
   echo " -clean Clean the build objects"
   echo " -bench Enable benchmark. (Default is disabled.)"
   echo " -attest [on|off] Enable remote attestation. (Default is on.)"
  exit 1
}

function clean() {
  pushd deps/rust-tpm-20-ref
  /bin/bash sh_script/build.sh -clean
  popd

  pushd deps/td-shim
  cargo clean
  popd

  pushd deps/rust-spdm
  cargo clean
  popd

  cargo clean
}

function build() {
  VTPM_FEATURES="td-logger/tdx"
  RENAME_SYMBOL_FLAG=""

  [[ "${ALGO}" != "" ]] && VTPM_FEATURES+=",${ALGO}"

  [[ ${ENABLE_BENCHMARK} == 1 ]] && VTPM_FEATURES+=",test_heap_size,test_stack_size"

  if [ "${REMOTE_ATTESTATION}" == "on" ]; then
    VTPM_FEATURES+=",remote-attestation"
    RENAME_SYMBOL_FLAG="-rename_symbol"
  fi

  pushd deps/rust-tpm-20-ref
  /bin/bash sh_script/build.sh -algo ${ALGO} ${RENAME_SYMBOL_FLAG}
  popd

  pushd deps/td-shim/devtools/td-layout-config
  cargo run -- -t memory ../../../../config/shim_layout.json -o ../../td-layout/src/runtime/exec.rs
  popd

  pushd deps/td-shim
  cargo xbuild -p td-shim \
    --target x86_64-unknown-none \
    --release --features=main,tdx \
    --no-default-features
  popd

  cargo xbuild \
    --target x86_64-unknown-none \
    --features=${VTPM_FEATURES} \
    -p vtpmtd --release

  pushd deps/td-shim
  cargo run -p td-shim-tools \
    --bin td-shim-ld --features=linker \
    --no-default-features \
    -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim \
    -p ../../target/x86_64-unknown-none/release/vtpmtd \
    -t executable \
    -m ../../config/metadata.json \
    -o target/x86_64-unknown-none/release/vtpmtd.bin

  cargo run -p td-shim-tools --features=enroller \
    --bin td-shim-enroll target/x86_64-unknown-none/release/vtpmtd.bin \
    -f 4fd44f20-0ee5-4362-9414-a04b32469bc9 ../../config/intel_root_sbx.der \
    -o ../../target/x86_64-unknown-none/release/vtpmtd.bin
  popd
}

while [[ $1 != "" ]]; do
  case "$1" in
    -algo)
      ALGO=$2
      shift
      ;;
    -clean)
      BUILD_OPT="clean"
      shift
      ;;
    -attest)
      REMOTE_ATTESTATION=$2
      shift
      ;;
    -bench)
      ENABLE_BENCHMARK=1
      shift
      ;;
   *)        usage;;
   esac
   shift
done

set -ex

export CC=clang
export AR=llvm-ar

case "${BUILD_OPT}" in
    clean) clean ;;
    build) build ;;

    *) echo "unknown build option - ${BUILD_OPT}" ;;
esac
