// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use core::convert::TryInto;

/// This file follow *TDX Guest Host Communication Interface(GHCI)* v1.5
use byteorder::{ByteOrder, LittleEndian};
use global::VtpmResult;
use td_uefi_pi::pi::guid::Guid;

use super::{COMMAND_REPORT_STATUS, DEFAULT_VERSION};

/// Table 5-16: vTPM TD SendCommunication Response
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
    pub const VERSION: usize = 0;
    pub const COMMAND: usize = 1;
    pub const RESERVED: Field = 2..4;
}

// pub const HEADER_LEN: usize = field::TDVM_ID.end;
pub const HEADER_LEN: usize = field::RESERVED.end;

/// Packet manage a buffer for protocol.
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }
    pub fn version(&self) -> u8 {
        let buf = self.buffer.as_ref();
        buf[field::VERSION]
    }
    pub fn command(&self) -> u8 {
        let buf = self.buffer.as_ref();
        buf[field::COMMAND]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_version(&mut self, value: u8) {
        let buf = self.buffer.as_mut();
        buf[field::VERSION] = value;
    }
    pub fn set_command(&mut self, value: u8) {
        let buf = self.buffer.as_mut();
        buf[field::COMMAND] = value;
    }
}
/// Build Respose Header at data_buffer
/// # Arguments
///
/// * `data_buffer` - data_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success and failed.
///
pub fn build_response_header(data_buffer: &mut [u8]) -> VtpmResult<usize> {
    let data_buffer_len = data_buffer.len();
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_REPORT_STATUS);
    Ok(HEADER_LEN)
}
