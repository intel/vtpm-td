// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use super::{COMMAND_WAIT_FOR_REQUEST, DEFAULT_VERSION};
/// This file follow *Trust Domain Extension (TDX) Virtual TPM Design Guide*
/// 5.1.7 vTPM TD WaitForCommunication
///
use byteorder::{ByteOrder, LittleEndian};
use global::VtpmResult;
use td_uefi_pi::pi::guid::Guid;

/// Table 5-15: vTPM TD WaitForCommunication Command
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
    pub const VERSION: usize = 0;
    pub const COMMAND: usize = 1;
    pub const RESERVED: Field = 2..4;
    pub const TDVM_ID: Field = 4..20;
}

pub const HEADER_LEN: usize = field::TDVM_ID.end;
/// Packet manage a buffer for protocol.
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
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
    pub fn set_tdvm_id(&mut self, vtpm_id: u128) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u128(&mut buf[field::TDVM_ID], vtpm_id);
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

/// Build Command Header at data_buffer
/// # Arguments
///
/// * `data_buffer` - data_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success and failed.
///
pub fn build_command_header(data_buffer: &mut [u8], vtpm_id: u128) -> VtpmResult<usize> {
    // TODO: check
    let data_buffer_len = data_buffer.len();
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_WAIT_FOR_REQUEST);
    packet.set_tdvm_id(vtpm_id);
    Ok(HEADER_LEN)
}
