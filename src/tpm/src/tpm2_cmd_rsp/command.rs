// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// pub const TPM_CMD_STARTUP: [u8; _] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];

use alloc::slice;

use super::TPM2_COMMAND_HEADER_SIZE;

#[repr(C, packed)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2CommandHeader {
    tag: u16,
    param_size: u32,
    command_code: u32,
}

impl Tpm2CommandHeader {
    pub fn new(tag: u16, param_size: u32, command_code: u32) -> Tpm2CommandHeader {
        Self {
            tag: tag.to_be(),
            param_size: param_size.to_be(),
            command_code: command_code.to_be(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Tpm2CommandHeader> {
        if bytes.len() < TPM2_COMMAND_HEADER_SIZE {
            log::error!(
                "Invalid length ({:?}) of tpm2 command header.\n",
                bytes.len()
            );
            return None;
        }

        let tag = u16::from_le_bytes([bytes[0], bytes[1]]);
        let param_size = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let command_code = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        Some(Tpm2CommandHeader {
            tag,
            param_size,
            command_code,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Tpm2CommandHeader as *const u8,
                core::mem::size_of::<Tpm2CommandHeader>(),
            )
        }
    }

    pub fn set_size(&mut self, size: u32) {
        self.param_size = size.to_be();
    }

    pub fn get_command_code(&self) -> u32 {
        self.command_code.to_be()
    }

    pub fn header_size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}
