// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(unused_imports))]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#[allow(unused, non_snake_case, non_upper_case_globals, non_camel_case_types)]
use core::{ffi::c_void, ptr::null_mut};

use global::{GLOBAL_TPM_DATA, TPM2_NV_SIZE};

use crate::tpm2_cmd_rsp::{
    command::Tpm2CommandHeader, response::Tpm2ResponseHeader, TPM2_COMMAND_HEADER_SIZE,
    TPM2_RESPONSE_HEADER_SIZE, TPM_CC_SHUTDOWN, TPM_SHUTDOWN_CMD,
};

extern crate alloc;

pub mod cty;
pub mod rtc;
pub mod std_lib;
pub mod tpm2_ca_cert;
pub mod tpm2_cmd_rsp;
pub mod tpm2_digests;
pub mod tpm2_provision;
pub mod tpm2_sys;

/// execute the tpm command
/// the first returned value indicates the size of response,
/// the second returned value is the response_code
pub fn execute_command(request: &[u8], response: &mut [u8], _vtpm_id: u128) -> (u32, u32) {
    let mut response_size = response.len() as u32;
    let mut response_ptr = response.as_mut_ptr();

    let mut buf: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
    buf.copy_from_slice(&request[..TPM2_COMMAND_HEADER_SIZE]);

    // log::info!("tpm cmd: {:02x?}\n", request);

    let tpm_cmd = Tpm2CommandHeader::from_bytes(&buf);
    if let Some(tpm_cmd) = tpm_cmd {
        GLOBAL_TPM_DATA.lock().last_tpm_cmd_code = Some(tpm_cmd.get_command_code());
        // log::info!(" cmd code: 0x{:x?}\n ", tpm_cmd.get_command_code());
    } else {
        log::error!("Invalid Tpm2CommandHeader!\n");
        log::error!("  {:02x?}\n", &buf);
        GLOBAL_TPM_DATA.lock().last_tpm_cmd_code = None;
        GLOBAL_TPM_DATA.lock().last_tpm_rsp_code = None;
        return (0, 0);
    }

    unsafe {
        tpm2_sys::_plat__RunCommand(
            request.len() as u32,
            request.as_ptr() as *mut u8,
            &mut response_size,
            &mut response_ptr,
        )
    }
    assert_eq!(response_ptr, response.as_mut_ptr());

    buf.copy_from_slice(&response[..TPM2_RESPONSE_HEADER_SIZE]);
    let tpm_rsp = Tpm2ResponseHeader::from_bytes(&buf);
    let rsp_code: u32;
    if let Some(tpm_rsp) = tpm_rsp {
        rsp_code = tpm_rsp.get_response_code();
        GLOBAL_TPM_DATA.lock().last_tpm_rsp_code = Some(rsp_code);
        // log::info!("rsp code: {:x?}\n", rsp_code);
    } else {
        log::error!("Invalid Tpm2ResponseHeader!\n");
        log::error!("  {:02x?}\n", &buf);
        GLOBAL_TPM_DATA.lock().last_tpm_rsp_code = None;
        return (0, 0);
    }

    // log::info!("tpm rsp: {:02x?}\n", &response[..response_size as usize]);

    (response_size, rsp_code)
}

pub fn start_tpm() {
    let mut first_time: i32 = 1;
    if GLOBAL_TPM_DATA.lock().provisioned {
        first_time = 0;
    }

    if first_time == 0 {
        // Write back the nv_mem which are back-up
        let mut nv_mem: [u8; TPM2_NV_SIZE + 4] = [0u8; TPM2_NV_SIZE + 4];
        let nv_size: u32 = TPM2_NV_SIZE as u32;
        nv_mem[..4].copy_from_slice(&nv_size.to_le_bytes());
        nv_mem[4..].copy_from_slice(GLOBAL_TPM_DATA.lock().tpm2_nv_mem());
        let ptr: *mut c_void = nv_mem.as_mut_ptr() as *mut c_void;

        unsafe {
            tpm2_sys::_plat__TPM_Terminate();
            tpm2_sys::_plat__TPM_Initialize(0, ptr);
        }
    } else {
        unsafe {
            tpm2_sys::_plat__TPM_Terminate();
            tpm2_sys::_plat__TPM_Initialize(1, null_mut());
        }
    }

    GLOBAL_TPM_DATA.lock().set_tpm_active(true);
}

pub fn terminate_tpm() {
    // If the last tpm command is not TPM_CC_SHUTDOWN, it has to be issued here.
    let last_tpm_command = GLOBAL_TPM_DATA.lock().last_tpm_cmd_code;
    if last_tpm_command.is_none() || last_tpm_command.unwrap() != TPM_CC_SHUTDOWN {
        let mut response: [u8; 32] = [0; 32];
        log::info!("shutdown the tpm\n");
        let _ = execute_command(&TPM_SHUTDOWN_CMD, &mut response, 0);
        // log::info!("response {0} bytes: {1:02x?}\n", response_size, response);
    }

    // Back-up the nv_mem before tpm terminate
    let mut nv_mem: [u8; TPM2_NV_SIZE] = [0u8; TPM2_NV_SIZE];
    let ptr: *mut c_void = nv_mem.as_mut_ptr() as *mut c_void;

    unsafe {
        tpm2_sys::_plat__NvMemoryRead(0, TPM2_NV_SIZE as u32, ptr);
    }

    let _ = GLOBAL_TPM_DATA.lock().set_nv_mem(&nv_mem);
    GLOBAL_TPM_DATA.lock().last_tpm_cmd_code = None;

    unsafe {
        tpm2_sys::_plat__TPM_Terminate();
    }
    GLOBAL_TPM_DATA.lock().set_tpm_active(false);
}
