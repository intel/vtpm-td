// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rust_tpm_20_ref_path = get_manifest_dir().join("../../deps/rust-tpm-20-ref");

    println!(
        "cargo:rustc-link-search=native={}",
        rust_tpm_20_ref_path
            .join("smallc/lib")
            .as_os_str()
            .to_str()
            .unwrap()
    );
    println!("cargo:rustc-link-lib=static=smallc");

    println!(
        "cargo:rustc-link-search=native={}",
        rust_tpm_20_ref_path
            .join("openssl-stubs")
            .as_os_str()
            .to_str()
            .unwrap()
    );
    println!("cargo:rustc-link-lib=static=crypto");

    println!(
        "cargo:rustc-link-search=native={}",
        rust_tpm_20_ref_path
            .join("tpm")
            .as_os_str()
            .to_str()
            .unwrap()
    );
    println!("cargo:rustc-link-lib=static=platform");
    println!("cargo:rustc-link-lib=static=tpm");
}

/// Get manifest directory.
fn get_manifest_dir() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(dir)
}
