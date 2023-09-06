// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::ffi::c_uchar;

use crypto::resolve::{get_cert_from_certchain, verify_peer_cert};
use global::{VtpmError, VtpmResult, GLOBAL_SPDM_DATA, GLOBAL_TPM_DATA};
use ring::digest;

use spdmlib::{
    config::MAX_SPDM_MSG_SIZE,
    crypto::{cert_operation, SpdmCertOperation},
    error::{SpdmResult, SPDM_STATUS_INVALID_CERT},
    responder::ResponderContext,
};
use tdx_tdcall::tdreport::{TdxReport, TD_REPORT_SIZE};
use tpm::{
    execute_command, start_tpm,
    tpm2_digests::TPM2_SHA384_SIZE,
    tpm2_sys::{_TPM_Hash_Data, _TPM_Hash_End, _TPM_Hash_Start},
};

fn spdm_secure_app_message_handler(
    _: &mut ResponderContext,
    session_id: u32,
    app_buffer: &[u8],
    auxiliary_app_data: &[u8],
) -> SpdmResult<([u8; MAX_SPDM_MSG_SIZE], usize)> {
    assert!(GLOBAL_SPDM_DATA.lock().valid);
    let tpm_cmd = app_buffer;
    let tpm_cmd_size = app_buffer.len();

    let mut tpm_rsp: [u8; MAX_SPDM_MSG_SIZE] = [0; MAX_SPDM_MSG_SIZE];

    let (rsp_size, rsp_code) = execute_command(tpm_cmd, &mut tpm_rsp, 0);

    Ok((tpm_rsp, rsp_size as usize))
}

pub fn register_spdm_secure_app_message_handler() -> bool {
    let mut handler = spdmlib::responder::app_message_handler::SpdmAppMessageHandler {
        dispatch_secured_app_message_cb: spdm_secure_app_message_handler,
    };

    spdmlib::responder::app_message_handler::register(handler)
}

pub fn gen_hcrtm_sequence(tdx_report: &[u8]) -> VtpmResult {
    if !GLOBAL_TPM_DATA.lock().tpm_active() {
        start_tpm();
        GLOBAL_TPM_DATA.lock().set_tpm_active(true);
    }

    // Before extending TdReport.ReportData and TdReport.Mac shall be zeroed.
    let mut report = TdxReport::default();
    report.as_bytes_mut().copy_from_slice(tdx_report);
    report.report_mac.mac.iter_mut().for_each(|m| *m = 0);
    report
        .report_mac
        .report_data
        .iter_mut()
        .for_each(|m| *m = 0);

    let td_report = report.as_bytes();

    let td_report_sha384 = digest::digest(&digest::SHA384, td_report);

    let mut data: [u8; TPM2_SHA384_SIZE] = [0; TPM2_SHA384_SIZE];
    data.copy_from_slice(td_report_sha384.as_ref());

    let ptr: *mut c_uchar = data.as_mut_ptr() as *mut c_uchar;

    unsafe {
        _TPM_Hash_Start();
        _TPM_Hash_Data(TPM2_SHA384_SIZE as u32, ptr);
        _TPM_Hash_End();
    }

    Ok(())
}

pub fn get_cert_from_cert_chain_cb(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    get_cert_from_certchain(cert_chain, index)
}

pub fn verify_cert_chain_cb(cert_chain: &[u8]) -> SpdmResult {
    let mut td_report: [u8; TD_REPORT_SIZE] = [0; TD_REPORT_SIZE];
    verify_peer_cert(cert_chain, &mut td_report)?;
    let res = gen_hcrtm_sequence(&td_report);
    if res.is_err() {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    Ok(())
}

pub fn register_spdm_cert_operation() -> bool {
    let mut handler = SpdmCertOperation {
        get_cert_from_cert_chain_cb,
        verify_cert_chain_cb,
    };

    cert_operation::register(handler)
}
