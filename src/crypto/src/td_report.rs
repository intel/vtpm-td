// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use tdx_tdcall::{
    td_call,
    tdreport::{TdxReport, TD_REPORT_SIZE},
    TdcallArgs,
};

const TDCALL_VERIFYREPORT: u64 = 22;
const TD_REPORT_MAC_SIZE: usize = 0x100;
const TD_REPORT_MAC_BUF_SIZE: usize = 2 * TD_REPORT_MAC_SIZE;

struct TdxReportMacBuf {
    buf: [u8; TD_REPORT_MAC_BUF_SIZE],
    start: usize,
    offset: usize,
    end: usize,
}

impl TdxReportMacBuf {
    fn new() -> Self {
        let mut buf = TdxReportMacBuf {
            buf: [0u8; TD_REPORT_MAC_BUF_SIZE],
            start: 0,
            offset: 0,
            end: 0,
        };
        buf.adjust();
        buf
    }

    fn adjust(&mut self) {
        self.start = self.buf.as_ptr() as *const u8 as usize;
        self.offset = TD_REPORT_MAC_SIZE - (self.start & (TD_REPORT_MAC_SIZE - 1));
        self.end = self.offset + TD_REPORT_MAC_SIZE;
    }

    fn report_mac_buf_start(&mut self) -> u64 {
        &mut self.buf[self.offset] as *mut u8 as u64
    }

    fn report_mac_buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..self.end]
    }
}

pub fn verify_td_report(td_report: &[u8]) -> SpdmResult {
    if td_report.len() != TD_REPORT_SIZE {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let mut td_report_mac = TdxReportMacBuf::new();
    td_report_mac.adjust();

    let addr = td_report_mac.report_mac_buf_start();
    td_report_mac
        .report_mac_buf_mut()
        .copy_from_slice(&td_report[..TD_REPORT_MAC_SIZE]);

    let mut args = TdcallArgs {
        rax: TDCALL_VERIFYREPORT,
        rcx: addr,
        ..Default::default()
    };

    let ret = td_call(&mut args);
    if ret != 0 {
        log::error!("tdcall_verifyreport failed with {:X?}\n", args.r10);
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let mut report = TdxReport::default();
    let mut all_zero = true;
    report.as_bytes_mut().copy_from_slice(td_report);
    for v in report.td_info.rtmr3.iter() {
        if *v != 0u8 {
            all_zero = false;
            break;
        }
    }

    if !all_zero {
        log::error!("rtmr3 is not all zero! - {:02x?}\n", report.td_info.rtmr3);
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    Ok(())
}
