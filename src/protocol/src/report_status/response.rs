// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use core::convert::TryInto;

/// This file follow *TDX Guest Host Communication Interface(GHCI)* v1.5
use byteorder::{ByteOrder, LittleEndian};
use global::{VtpmError, VtpmResult};
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

// pub const HEADER_LEN: usize = field::TPM_ID.end;
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
    if data_buffer_len < HEADER_LEN {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_REPORT_STATUS);
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod test {
    use super::*;

    const BUFFER_SIZE: usize = 0x100;

    #[test]
    fn test_packet() {
        let mut data_buffer = [0u8; BUFFER_SIZE];
        let version = 100 as u8;
        let command = 0xff as u8;
        let mut packet = Packet::new_unchecked(&mut data_buffer);
        packet.set_version(version);
        packet.set_command(command);
        assert_eq!(packet.version(), version);
        assert_eq!(packet.command(), command);
        let version1 = 32;
        packet.as_mut()[field::VERSION] = version1;
        assert_eq!(packet.as_ref()[field::VERSION], version1);
    }

    #[test]
    fn test_build_response_header() {
        let mut buffer = [0u8; BUFFER_SIZE];
        let res = build_response_header(&mut buffer);
        assert_eq!(res.unwrap(), HEADER_LEN);
    }

    #[test]
    fn test_zerodata() {
        let res = build_response_header(&mut []);
        assert!(res.is_err());
    }
}
