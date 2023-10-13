// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::slice;
use global::VtpmError;
use td_payload::mm::dma::DmaMemory;
use tdx_tdcall::tdx::tdvmcall_get_quote;

use crate::ghci::{set_vmm_notification, wait_for_vmm_notification};

const TDX_REPORT_LEN: u32 = 1024;
const TDX_QUOTE_LEN: usize = 4 * 4096 - 28;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct QgsMsgHeader {
    major_version: u16, // TDX major version
    minor_version: u16, // TDX minor version
    msg_type: u32,      // GET_QUOTE_REQ or GET_QUOTE_RESP
    size: u32,          // size of the whole message, include this header, in byte
    error_code: u32,    // used in response only
}

impl QgsMsgHeader {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const QgsMsgHeader as *const u8,
                QgsMsgHeader::size_of(),
            )
        }
    }

    fn size_of() -> usize {
        core::mem::size_of::<Self>()
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct QgsMsgGetQuoteReq {
    header: QgsMsgHeader,                          // header.type = GET_QUOTE_REQ
    report_size: u32,                              // cannot be 0
    id_list_size: u32,                             // length of id_list, in byte, can be 0
    report_id_list: [u8; TDX_REPORT_LEN as usize], // report followed by id list
}

impl QgsMsgGetQuoteReq {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const QgsMsgGetQuoteReq as *const u8,
                core::mem::size_of::<QgsMsgGetQuoteReq>(),
            )
        }
    }

    fn size_of() -> usize {
        core::mem::size_of::<Self>()
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct TdxQuoteHdr {
    version: u64,               // Quote version, filled by TD
    status: u64,                // Status code of Quote request, filled by VMM
    in_len: u32,                // Length of TDREPORT, filled by TD
    out_len: u32,               // Length of Quote, filled by VMM
    data_len_be_bytes: [u8; 4], // big-endian 4 bytes indicate the size of data following
    data: [u8; TDX_QUOTE_LEN],  // Actual Quote data or TDREPORT on input
}

impl TdxQuoteHdr {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const TdxQuoteHdr as *const u8,
                core::mem::size_of::<TdxQuoteHdr>(),
            )
        }
    }

    fn size_of() -> usize {
        core::mem::size_of::<Self>()
    }

    fn data_len(&self) -> u32 {
        u32::from_be_bytes(self.data_len_be_bytes)
    }

    fn status(&self) -> u64 {
        self.status
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct QgsMsgGetQuoteRsp {
    header: QgsMsgHeader,          // header.type = GET_QUOTE_RESP
    selected_id_size: u32,         // can be 0 in case only one id is sent in request
    quote_size: u32,               // length of quote_data, in byte
    id_quote: [u8; TDX_QUOTE_LEN], // selected id followed by quote
}

impl QgsMsgGetQuoteRsp {
    fn is_ok(&self) -> bool {
        self.header.major_version == 1
            && self.header.minor_version == 0
            && self.header.msg_type == 1
            && self.header.error_code == 0
    }
}

fn generate_qgs_quote_msg(report: &[u8]) -> QgsMsgGetQuoteReq {
    //build quote service message header to be used by QGS
    let qgs_header = QgsMsgHeader {
        major_version: 1,
        minor_version: 0,
        msg_type: 0,
        size: 16 + 8 + TDX_REPORT_LEN, // header + report_size and id_list_size + TDX_REPORT_LEN
        error_code: 0,
    };

    //build quote service message body to be used by QGS
    let mut qgs_request = QgsMsgGetQuoteReq {
        header: qgs_header,
        report_size: TDX_REPORT_LEN,
        id_list_size: 0,
        report_id_list: [0; TDX_REPORT_LEN as usize],
    };

    qgs_request.report_id_list.copy_from_slice(report);

    qgs_request
}

pub fn tdx_get_quote(report_data: &[u8]) -> Result<alloc::vec::Vec<u8>, VtpmError> {
    let quote_header_len = TdxQuoteHdr::size_of();

    //build QGS request message
    let qgs_msg_get_quote_req = generate_qgs_quote_msg(report_data);

    //build quote generation request header
    let mut quote_header = TdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: (core::mem::size_of_val(&qgs_msg_get_quote_req) + 4) as u32,
        out_len: 0,
        data_len_be_bytes: (QgsMsgGetQuoteReq::size_of() as u32).to_be_bytes(),
        data: [0; TDX_QUOTE_LEN],
    };

    quote_header.data[0..QgsMsgGetQuoteReq::size_of()]
        .copy_from_slice(qgs_msg_get_quote_req.as_slice());

    // allocate shared memory to host the quote_header
    let mut shared = if let Some(shared) = DmaMemory::new(quote_header_len / 0x1000) {
        shared
    } else {
        log::error!("Allocate Shared memory failed!!!");
        return Err(VtpmError::OutOfResource);
    };
    shared.as_mut_bytes()[..quote_header_len].copy_from_slice(quote_header.as_slice());

    // log::info!("req: {:02x?}\n", &shared.as_mut_bytes()[..28]);

    set_vmm_notification();

    // Call tdvmcall to get quote
    if tdvmcall_get_quote(shared.as_mut_bytes()).is_err() {
        log::error!("tdvmcall to get_quote failed.\n");
        return Err(VtpmError::VmmError);
    }

    wait_for_vmm_notification();

    // log::info!("rsp: {:02x?}\n", &shared.as_mut_bytes()[..28]);
    let quote_hdr_rsp = unsafe {
        let raw_ptr = shared.as_mut_bytes().as_mut_ptr() as *mut TdxQuoteHdr;
        raw_ptr.as_mut().unwrap() as &mut TdxQuoteHdr
    };

    if quote_hdr_rsp.status() != 0 {
        log::error!(
            "Failed to call tdvmcall to get_quote. {:x?}\n",
            quote_hdr_rsp.status()
        );
        return Err(VtpmError::VmmError);
    }

    let out_len = quote_hdr_rsp.out_len;
    let qgs_msg_resp_size = quote_hdr_rsp.data_len();

    let qgs_msg_rsp = unsafe {
        let raw_ptr = quote_hdr_rsp.data.as_mut_ptr() as *mut QgsMsgGetQuoteRsp;
        raw_ptr.as_mut().unwrap() as &mut QgsMsgGetQuoteRsp
    };

    if out_len - qgs_msg_resp_size != 4 {
        log::error!("[get_tdx_quote] Fail to get TDX quote: wrong TDX quote size!");
        return Err(VtpmError::VmmError);
    }

    if !qgs_msg_rsp.is_ok() {
        log::error!("Fail to get TDX quote: QGS response error!\n");
        log::error!("QGS response header: {:?}\n", qgs_msg_rsp.header);
        return Err(VtpmError::VmmError);
    }

    // log::info!("qgs_msg_rsp.header: {:?}\n", qgs_msg_rsp.header);
    let mut quote: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    quote.extend_from_slice(&qgs_msg_rsp.id_quote[..qgs_msg_rsp.quote_size as usize]);

    // log::info!("quote len: {:?}\n", quote.len());

    Ok(quote.to_vec())
}
