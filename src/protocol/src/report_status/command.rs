// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use super::{COMMAND_REPORT_STATUS, DEFAULT_VERSION};
/// This file follow *Trust Domain Extension (TDX) Virtual TPM Design Guide*
/// 5.1.8 vTPM TD SendCommunication
///
use byteorder::{ByteOrder, LittleEndian};
use global::{VtpmError, VtpmResult};
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
    pub const TPM_ID: Field = 4..20;
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
    pub fn set_tpm_id(&mut self, vtpm_id: u128) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u128(&mut buf[field::TPM_ID], vtpm_id);
    }
    pub fn set_data(&mut self, data: &[u8]) -> VtpmResult<usize> {
        let buf = self.buffer.as_mut();
        let buf_data_len = buf.len() - HEADER_LEN;
        let data_len = data.len();
        if data_len > buf_data_len {
            return Err(VtpmError::InvalidParameter);
        }
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
    let dest_buffer_len = dest_buffer.len();
    let total_size = HEADER_LEN + data_buffer_len;
    if dest_buffer_len < total_size {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(dest_buffer);
    packet.set_version(DEFAULT_VERSION);
    packet.set_command(COMMAND_REPORT_STATUS);
    packet.set_status(status);
    packet.set_tpm_id(vtpm_id);
    packet.set_operation(operation);
    let mut data_len = 0;
    if data_buffer_len != 0 {
        data_len = packet.set_data(data_buffer)?;
    }
    Ok(data_len + HEADER_LEN)
}

#[cfg(test)]
mod test {
    use super::*;

    const BUFFER_SIZE: usize = 0x1000;
    const DATA_SIZE: usize = 0x100;
    const INVALID_DATA_SIZE: usize = 0x2000;

    #[test]
    fn test_packet() {
        let mut buffer = [1u8; BUFFER_SIZE];
        let mut packet = Packet::new_unchecked(&mut buffer);
        let version = 99;
        let command = 0xff;
        let status = 1;
        let vtpm_id = 0x10000 as u128;
        let operation = 0 as u8;
        let data = [0x11u8; DATA_SIZE];
        packet.set_version(version);
        packet.set_command(command);
        packet.set_status(status);
        packet.set_tpm_id(vtpm_id);
        packet.set_operation(operation);
        let data_len = packet.set_data(&data);
        assert_eq!(data_len.unwrap(), data.len());

        assert_eq!(packet.as_ref()[field::DATA][0..data.len()], data);
        assert_eq!(packet.as_ref()[field::VERSION], version);
        assert_eq!(packet.as_ref()[field::COMMAND], command);
        assert_eq!(packet.as_ref()[field::STATUS], status);
        assert_eq!(packet.as_ref()[field::OPERATION], operation);
        let version1 = 111;
        packet.as_mut()[field::VERSION] = version1;
        assert_eq!(packet.as_ref()[field::VERSION], version1);
        let invalid_data = [1u8; INVALID_DATA_SIZE];
        let res = packet.set_data(&invalid_data);
        assert!(res.is_err());
        assert_eq!(LittleEndian::read_u128(&mut buffer[field::TPM_ID]), vtpm_id);
    }

    #[test]
    fn test_build_cmd() {
        let mut buffer = [0xffu8; BUFFER_SIZE];
        let status = 1;
        let vtpm_id = 0x10000 as u128;
        let operation = 0 as u8;
        let data: [u8; DATA_SIZE] = [0x11; DATA_SIZE];
        let res = build_command(vtpm_id, operation, status, &data, &mut buffer);
        assert_eq!(res.unwrap(), data.len() + HEADER_LEN);
        assert_eq!(buffer[field::STATUS], status);
        assert_eq!(buffer[field::OPERATION], operation);
        assert_eq!(LittleEndian::read_u128(&mut buffer[field::TPM_ID]), vtpm_id);
        assert_eq!(buffer[field::DATA][0..data.len()], data);
    }

    #[test]
    fn test_zerodata() {
        let mut buffer = [0xffu8; BUFFER_SIZE];
        let status = 1;
        let vtpm_id = 0x10000 as u128;
        let operation = 0 as u8;
        let res = build_command(vtpm_id, operation, status, &[], &mut buffer);
        assert_eq!(res.is_err(), false);
    }

    #[test]
    fn test_invalid_data() {
        let mut buffer = [0xffu8; BUFFER_SIZE];
        let status = 1;
        let vtpm_id = 0x10000 as u128;
        let operation = 0 as u8;
        let data = [1u8; INVALID_DATA_SIZE];
        let res = build_command(vtpm_id, operation, status, &data, &mut buffer);
        assert!(res.is_err());
    }

    #[test]
    fn tese_zerodest() {
        let data: [u8; DATA_SIZE] = [0xff; DATA_SIZE];
        let status = 1;
        let vtpm_id = 0x10000 as u128;
        let operation = 0 as u8;
        let res = build_command(vtpm_id, operation, status, &data, &mut []);
        assert!(res.is_err());
    }
}
