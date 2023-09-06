// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// pub const TPM_CMD_STARTUP: [u8; _] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];

use alloc::slice;

use super::TPM2_RESPONSE_HEADER_SIZE;

#[repr(C, packed)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2ResponseHeader {
    tag: u16,
    param_size: u32,
    response_code: u32,
}

impl Tpm2ResponseHeader {
    pub fn new(tag: u16, param_size: u32, response_code: u32) -> Tpm2ResponseHeader {
        Self {
            tag: tag.to_be(),
            param_size: param_size.to_be(),
            response_code: response_code.to_be(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Tpm2ResponseHeader> {
        if bytes.len() < TPM2_RESPONSE_HEADER_SIZE {
            log::error!(
                "Invalid length ({:?}) of tpm2 response header.\n",
                bytes.len()
            );
            return None;
        }

        let tag = u16::from_le_bytes([bytes[0], bytes[1]]);
        let param_size = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let response_code = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        Some(Tpm2ResponseHeader {
            tag,
            param_size,
            response_code,
        })
    }

    pub fn get_response_code(&self) -> u32 {
        self.response_code.to_be()
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Tpm2ResponseHeader as *const u8,
                core::mem::size_of::<Tpm2ResponseHeader>(),
            )
        }
    }

    pub fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}
