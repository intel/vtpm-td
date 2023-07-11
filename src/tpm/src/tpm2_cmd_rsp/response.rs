// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// pub const TPM_CMD_STARTUP: [u8; _] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];

use super::TPM2_RESPONSE_HEADER_SIZE;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2ResponseHeader {
    pub tag: u16,
    pub param_size: u32,
    pub response_code: u32,
}

impl Tpm2ResponseHeader {
    pub fn from_bytes(bytes: &[u8]) -> Option<Tpm2ResponseHeader> {
        if bytes.len() < TPM2_RESPONSE_HEADER_SIZE {
            log::error!(
                "Invalid length ({:?}) of tpm2 response header.\n",
                bytes.len()
            );
            return None;
        }
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let param_size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let response_code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        Some(Tpm2ResponseHeader {
            tag,
            param_size,
            response_code,
        })
    }

    pub fn to_bytes(&self, out_buffer: &mut [u8]) -> Option<usize> {
        if out_buffer.len() < TPM2_RESPONSE_HEADER_SIZE {
            log::error!("Invalid size({:?}) of input buffer\n", out_buffer.len());
            return None;
        }

        let tag = self.tag.to_le_bytes();
        let param_size = self.param_size.to_be_bytes();
        let response_code = self.response_code.to_be_bytes();

        out_buffer[..2].copy_from_slice(&tag);
        out_buffer[2..6].copy_from_slice(&param_size);
        out_buffer[6..TPM2_RESPONSE_HEADER_SIZE].copy_from_slice(&response_code);

        Some(TPM2_RESPONSE_HEADER_SIZE)
    }
}
