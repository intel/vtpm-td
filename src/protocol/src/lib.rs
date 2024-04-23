// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]

pub mod report_status;
/// This file follow *TDX Guest Host Communication Interface(GHCI)* v1.5

/// TDG.VP.VMCALL<Service> Protocol
pub mod service;
pub mod wait_for_request;

use td_shim_interface::td_uefi_pi::pi::guid::Guid;

/// Section 5.2: vTPM TD VMCALL<Service.VTPMTD>
/// {0xc3c87a08, 0x3b4a, 0x41ad, 0xa5, 0x2d, 0x96, 0xf1, 0x3c, 0xf8, 0x9a, 0x66}
#[allow(unused)]
pub static SERVICE_VTPMTD_GUID: Guid = Guid::from_fields(
    0xc3c87a08,
    0x3b4a,
    0x41ad,
    [0xa5, 0x2d, 0x96, 0xf1, 0x3c, 0xf8, 0x9a, 0x66],
);
