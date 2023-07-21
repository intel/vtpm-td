// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

/// This file follow *TDX Guest Host Communication Interface(GHCI)* v1.5
use byteorder::{ByteOrder, LittleEndian};
use global::{VtpmError, VtpmResult};
use td_uefi_pi::pi::guid::Guid;

/// Table 3-40: TDG.VP.VMCALL< Service >-command buffer layout
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;

    pub const GUID: Field = 0..16;
    pub const LENGTH: Field = 16..20;
    pub const RESERVED: Field = 20..24;
    pub const DATA: Rest = 24..;
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
    pub fn set_guid(&mut self, guid: Guid) {
        let buf = self.buffer.as_mut();
        let guid_bytes = guid.as_bytes();
        let guid_bytes_len = guid_bytes.len();
        assert_eq!(guid_bytes_len, field::GUID.len());
        buf[field::GUID].copy_from_slice(&guid_bytes[..])
    }
    pub fn set_length(&mut self, length: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::LENGTH], length);
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
/// * `service_guid` - A service GUID: example
/// * `data_buffer` - data_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success and failed.
///
pub fn build_command_header(service_guid: Guid, data_buffer: &mut [u8]) -> VtpmResult<usize> {
    // TODO: check
    let data_buffer_len = data_buffer.len();
    if data_buffer_len < HEADER_LEN {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_guid(service_guid);
    packet.set_length(data_buffer_len as u32);
    Ok(data_buffer_len)
}

/// Build Command Header at data_buffer and return data_buffer size
/// # Arguments
///
/// * `service_guid` - A service GUID: example
/// * `data_buffer` - data_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success with lenght and otherwise failed.
///
pub fn build_command_header_and_size(
    service_guid: Guid,
    data_buffer: &mut [u8],
) -> VtpmResult<usize> {
    // TODO: check
    let data_buffer_len = data_buffer.len();
    if data_buffer_len < HEADER_LEN {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_guid(service_guid);
    packet.set_length(data_buffer_len as u32);
    Ok(data_buffer_len)
}
