// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use super::{COMMAND_REPORT_STATUS, DEFAULT_VERSION};
/// This file follow *Trust Domain Extension (TDX) Virtual TPM Design Guide*
/// 5.1.8 vTPM TD SendCommunication
///
use byteorder::{ByteOrder, LittleEndian};
use global::VtpmResult;
use td_uefi_pi::pi::guid::Guid;

/// TODO: FIXME: comment reference error!
/// Table 5-15: vTPM TD WaitForCommunication Command
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
    pub const VERSION: usize = 0;
    pub const COMMAND: usize = 1;
    pub const OPERATION: usize = 2;
    pub const STATUS: usize = 3;
    pub const TDVM_ID: Field = 4..20;
    pub const DATA: Rest = 20..;
}

pub const HEADER_LEN: usize = field::DATA.start;
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
    pub fn set_operation(&mut self, value: u8) {
        let buf = self.buffer.as_mut();
        buf[field::OPERATION] = value;
    }
    pub fn set_status(&mut self, value: u8) {
        let buf = self.buffer.as_mut();
        buf[field::STATUS] = value;
    }
    pub fn set_tdvm_id(&mut self, vtpm_id: u128) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u128(&mut buf[field::TDVM_ID], vtpm_id);
    }
    pub fn set_data(&mut self, data: &[u8]) -> VtpmResult<usize> {
        // TODO: check
        let buf = self.buffer.as_mut();
        let data_len = data.len();
        buf[field::DATA][0..data_len].copy_from_slice(data);
        Ok(data_len)
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

/// Build Command at dest_buffer
/// # Arguments
///
/// * `dest_buffer` - dest_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success with length and failed with error.
///
pub fn build_command(
    vtpm_id: u128,
    operation: u8,
    status: u8,
    data_buffer: &[u8],
    dest_buffer: &mut [u8],
) -> VtpmResult<usize> {
    let data_buffer_len = data_buffer.len();
    let mut packet = Packet::new_unchecked(dest_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_REPORT_STATUS);
    packet.set_status(status);
    packet.set_tdvm_id(vtpm_id);
    packet.set_operation(operation);
    let mut data_len = 0;
    if data_buffer_len != 0 {
        data_len = packet.set_data(data_buffer)?;
    }
    Ok(data_len + HEADER_LEN)
}
