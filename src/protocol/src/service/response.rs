// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use core::convert::TryInto;

/// This file follow *TDX Guest Host Communication Interface(GHCI)* v1.5
use byteorder::{ByteOrder, LittleEndian};
use global::{VtpmError, VtpmResult};
use td_uefi_pi::pi::guid::Guid;

/// Common Status Code for response.
pub const STATUS_COMMAND_SENT_RESPONSE_RETURNED: u32 = 0x0;
pub const STATUS_DEVICE_ERROR: u32 = 0x1;
pub const STATUS_TIMEOUT: u32 = 0x2;
pub const STATUS_RESPONSE_BUFFER_TOO_SMALL: u32 = 0x3;
pub const STATUS_BAD_COMMAND_BUFFER_SIZE: u32 = 0x4;
pub const STATUS_BAD_RESPONSE_BUFFER_SIZE: u32 = 0x5;
pub const STATUS_SERVICE_BUSY: u32 = 0x6;
pub const STATUS_INVALID_PARAMETER: u32 = 0x7;
pub const STATUS_OUT_OF_RESOURCE: u32 = 0x8;
pub const STATUS_UNSUPPORTED: u32 = 0xFFFF_FFFF;

/// Table 3-41: TDG.VP.VMCALL< Service >-response buffer layout
pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
    pub const GUID: Field = 0..16;
    pub const LENGTH: Field = 16..20;
    pub const STATUS: Field = 20..24;
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
    pub fn guid(&self) -> Guid {
        let buf = self.as_ref();
        assert_eq!(field::GUID.len(), 16);
        Guid::from_bytes(buf[field::GUID].try_into().unwrap())
    }
    pub fn length(&self) -> u32 {
        let buf = self.as_ref();
        LittleEndian::read_u32(&buf[field::LENGTH])
    }
    pub fn status(&self) -> u32 {
        let buf = self.as_ref();
        LittleEndian::read_u32(&buf[field::STATUS])
    }

    pub fn data(&self) -> &[u8] {
        let buf = self.buffer.as_ref();
        let end = self.length() as usize;
        &buf[field::DATA.start..end]
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

/// Build Response Header at data_buffer
/// # Arguments
///
/// * `service_guid` - A service GUID: example
/// * `data_buffer` - data_buffer contains header and data. data_buffer = header + data.
///
/// # Returns
/// return success and failed.
///
pub fn build_response_header(service_guid: Guid, data_buffer: &mut [u8]) -> VtpmResult<usize> {
    let data_buffer_len = data_buffer.len();
    if data_buffer_len < HEADER_LEN {
        return Err(VtpmError::InvalidParameter);
    }
    let mut packet = Packet::new_unchecked(data_buffer);
    packet.set_guid(service_guid);
    packet.set_length(data_buffer_len as u32);
    Ok(data_buffer_len)
}
