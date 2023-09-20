// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use super::{COMMAND_WAIT_FOR_REQUEST, DEFAULT_VERSION};
/// This file follow *Trust Domain Extension (TDX) Virtual TPM Design Guide*
/// 5.1.7 vTPM TD WaitForCommunication
///
use byteorder::{ByteOrder, LittleEndian};
use global::{VtpmError, VtpmResult};
use td_uefi_pi::pi::guid::Guid;

/// Table 5-15: vTPM TD WaitForCommunication Command
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
    pub const VERSION: usize = 0;
    pub const COMMAND: usize = 1;
    pub const RESERVED: Field = 2..4;
    pub const TPM_ID: Field = 4..20;
}

pub const HEADER_LEN: usize = field::TPM_ID.end;
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
    pub fn set_tpm_id(&mut self, vtpm_id: u128) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u128(&mut buf[field::TPM_ID], vtpm_id);
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
    let data_buffer_len = data_buffer.len();
    if data_buffer_len < HEADER_LEN {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_WAIT_FOR_REQUEST);
    packet.set_tpm_id(vtpm_id);
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod test {
    use super::*;

    const BUFFER_SIZE: usize = 0x1000;
    const PACKET_BUFFER_SIZE: usize = 0x100;
    const INVALID_DATA_BUFFER_SIZE: usize = HEADER_LEN - 1;

    #[test]
    fn test_packet() {
        let mut data_buffer = [0u8; PACKET_BUFFER_SIZE];
        let version = 100 as u8;
        let command = 0xff as u8;
        let vtpm_id = 100;
        let mut packet = Packet::new_unchecked(&mut data_buffer);
        packet.set_version(version);
        packet.set_command(command);
        packet.set_tpm_id(vtpm_id);
        assert_eq!(packet.as_ref()[field::VERSION], version);
        let version_2 = 1;
        packet.as_mut()[field::VERSION] = version_2;
        assert_eq!(version_2, packet.as_ref()[field::VERSION]);
        assert_eq!(data_buffer[field::COMMAND], command);
        assert_eq!(
            LittleEndian::read_u128(&data_buffer[field::TPM_ID]),
            vtpm_id
        );
    }

    #[test]
    fn test_build_cmd_header() {
        let mut data_buffer = [0u8; BUFFER_SIZE];
        let vtpmid = 101 as u128;
        let res = build_command_header(&mut data_buffer, vtpmid);
        assert_eq!(res.unwrap(), HEADER_LEN);
        assert_eq!(LittleEndian::read_u128(&data_buffer[field::TPM_ID]), vtpmid);
    }

    #[test]
    fn test_zerodata() {
        let res = build_command_header(&mut [], 0);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_data() {
        let mut data_buffer: [u8; INVALID_DATA_BUFFER_SIZE] = [0; INVALID_DATA_BUFFER_SIZE];
        let res = build_command_header(&mut data_buffer, 0);
        assert!(res.is_err());
    }
}
