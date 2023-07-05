// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod resolve;
pub mod td_report;
pub mod x509;

pub const MUTUAL_ATTESTATION_ERROR: &str = "MutualAttestationError";
