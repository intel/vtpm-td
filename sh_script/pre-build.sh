# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

#!/bin/sh

function patch_tdshim() {
  pushd deps/td-shim
  sh_script/preparation.sh
  popd
}

function patch_rustspdm() {
  pushd deps/rust-spdm
  sh_script/pre-build.sh
  popd
}

function patch_mstpm20ref() {
  pushd deps/rust-tpm-20-ref
  sh_script/pre-build.sh
  popd
}

patch_tdshim
patch_rustspdm
patch_mstpm20ref