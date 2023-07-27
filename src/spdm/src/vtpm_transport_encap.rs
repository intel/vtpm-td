// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use codec::{enum_builder, Codec, EncodeErr, Reader, Writer};
use spdmlib::{
    common::SpdmTransportEncap,
    error::{SpdmResult, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_LOCAL},
};

enum_builder! {
    @U8
    EnumName: VtpmTransportMessageType;
    EnumVal{
        VtpmTransportMessageTypeSpdm => 0x01,
        VtpmTransportMessageTypeSecureSpdm => 0x02
    }
}

enum_builder! {
    @U8
    EnumName: VtpmTransportAppMessageType;
    EnumVal{
        VtpmTransportAppMessageTypeSpdm => 0x01,
        VtpmTransportAppMessageTypeTpm => 0x03
    }
}

pub const VTPM_SEQUENCE_NUM_COUNT: u8 = 8;
pub const VTPM_MAX_RANDOME_DATA_COUNT: u16 = 16;

/// Follow table 5-16
#[derive(Clone, Copy, Debug)]
pub struct VtpmTransportAppMessageHeader {
    pub message_type: VtpmTransportAppMessageType,
}

impl Codec for VtpmTransportAppMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        self.message_type.encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<VtpmTransportAppMessageHeader> {
        let message_type = VtpmTransportAppMessageType::read(r)?;

        Some(VtpmTransportAppMessageHeader { message_type })
    }
}

/// Follow table 5-14
#[derive(Clone, Copy, Debug)]
pub struct VtpmTransportMessageHeader {
    pub message_length: u16,
    pub version: u8,
    pub message_type: VtpmTransportMessageType,
}

impl Codec for VtpmTransportMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        let _ = self.message_length.encode(bytes);
        let _ = self.version.encode(bytes);
        self.message_type.encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<VtpmTransportMessageHeader> {
        let message_length = u16::read(r)?;
        let version = u8::read(r)?;
        let message_type = VtpmTransportMessageType::read(r)?;

        Some(VtpmTransportMessageHeader {
            message_length,
            version,
            message_type,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct VtpmTransportEncap {}

impl SpdmTransportEncap for VtpmTransportEncap {
    /// Encap the input AEAD data with a VtpmTransportMessageHeader
    /// The output transport_buffer follows table 5-14/15
    /// Note: the data is encrypted.
    fn encap(
        &mut self,
        spdm_buffer: &[u8],
        transport_buffer: &mut [u8],
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut writer = Writer::init(&mut *transport_buffer);
        let vtpm_transport_header = VtpmTransportMessageHeader {
            message_length: (2 + payload_len) as u16,
            version: 1,
            message_type: if secured_message {
                VtpmTransportMessageType::VtpmTransportMessageTypeSecureSpdm
            } else {
                VtpmTransportMessageType::VtpmTransportMessageTypeSpdm
            },
        };
        let _ = vtpm_transport_header.encode(&mut writer);

        let header_size = writer.used();
        if transport_buffer.len() < header_size + payload_len {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + payload_len)
    }

    /// Decap the input transport_buffer (Table 5-14/15)
    /// The output spdm_buffer follows Table 5-15.
    /// The output bool indicates if it is secure SPDM or not.
    /// Note: the data is encrypted.
    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(transport_buffer);
        let mut secured_message: bool = false;

        match VtpmTransportMessageHeader::read(&mut reader) {
            Some(vtpm_transport_header) => {
                if vtpm_transport_header.message_type
                    == VtpmTransportMessageType::VtpmTransportMessageTypeSecureSpdm
                {
                    secured_message = true;
                }
            }
            None => {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            } // return spdm_result_err!(EIO),
        }

        let header_size = reader.used();

        if header_size > transport_buffer.len() {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let payload_size = transport_buffer.len() - header_size;

        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);

        Ok((payload_size, secured_message))
    }

    /// Encap the input app_message to app_data (T + app_message).
    /// It follows table 5-16.
    /// T = is_app_message == true ? 3 : 1.
    /// Note: the data is of plain-text.
    fn encap_app(
        &mut self,
        app_message: &[u8],
        app_data: &mut [u8],
        is_app_message: bool,
    ) -> SpdmResult<usize> {
        let app_message_len = app_message.len();
        let mut writer = Writer::init(&mut *app_data);
        let header = VtpmTransportAppMessageHeader {
            message_type: if is_app_message {
                VtpmTransportAppMessageType::VtpmTransportAppMessageTypeTpm
            } else {
                VtpmTransportAppMessageType::VtpmTransportAppMessageTypeSpdm
            },
        };
        let _ = header.encode(&mut writer);

        let header_size = writer.used();
        if app_data.len() < app_message_len + header_size {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        app_data[header_size..(header_size + app_message_len)].copy_from_slice(app_message);
        Ok(header_size + app_message_len)
    }

    /// Decap the input app_data(T + app_message) to app_message.
    /// It follows table 5-16.
    /// if app_data[0] == 1, then returned bool is false (is_app_message=false).
    /// if app_data[0] == 3, then returned bool is true (is_app_message=true).
    /// Note: the data is of plain-text.
    fn decap_app(&mut self, app_data: &[u8], app_message: &mut [u8]) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(app_data);
        let mut is_app_message = false;

        match VtpmTransportAppMessageHeader::read(&mut reader) {
            Some(header) => {
                if header.message_type
                    == VtpmTransportAppMessageType::VtpmTransportAppMessageTypeTpm
                {
                    is_app_message = true;
                }
            }
            None => {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            } // return spdm_result_err!(EIO),
        }

        let header_size = reader.used();
        assert!(header_size == 1);

        let app_message_size = app_data.len() - header_size;
        if app_message.len() < app_message_size {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }
        app_message[..app_message_size].copy_from_slice(&app_data[header_size..]);

        Ok((app_message_size, is_app_message))
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        VTPM_SEQUENCE_NUM_COUNT
    }
    fn get_max_random_count(&mut self) -> u16 {
        VTPM_MAX_RANDOME_DATA_COUNT
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const DATA_SIZE: usize = 0x100;
    const TEST_SPDM_BUFFER_SIZE: usize = 0x100;
    const TEST_TRANSPORT_BUFFER_SIZE: usize = 0x1024;
    const INVALID_TEST_TRANSPORT_BUFFER_SIZE: usize = 0x10;
    const VTPM_MESSAGE_HEADER_SIZE: usize = 4;
    const VTPM_APP_MESSAGE_HEADER_SIZE: usize = 1;

    #[test]
    fn test_get_sequence_number_count() {
        let mut vtpmtransport: VtpmTransportEncap = VtpmTransportEncap::default();
        assert_eq!(
            vtpmtransport.get_sequence_number_count(),
            VTPM_SEQUENCE_NUM_COUNT
        );
    }

    #[test]
    fn test_get_max_random_count() {
        let mut vtpmtransport: VtpmTransportEncap = VtpmTransportEncap::default();
        assert_eq!(
            vtpmtransport.get_max_random_count(),
            VTPM_MAX_RANDOME_DATA_COUNT
        );
    }

    #[test]
    fn test_vtpmtransport_appmessage_header() {
        let test: VtpmTransportAppMessageHeader = VtpmTransportAppMessageHeader {
            message_type: VtpmTransportAppMessageType::VtpmTransportAppMessageTypeSpdm,
        };
        let mut bytes = [1u8; DATA_SIZE];
        let mut writer = Writer::init(&mut bytes);
        let res = test.encode(&mut writer);
        assert_eq!(res.is_err(), false);
        let bytes = [1u8; DATA_SIZE];
        let mut reader = Reader::init(&bytes);
        let res = VtpmTransportAppMessageHeader::read(&mut reader);
        assert_eq!(res.is_none(), false);
    }

    #[test]
    fn test_vtpmtransport_message_header() {
        let test = VtpmTransportMessageHeader {
            message_length: 2,
            version: 1,
            message_type: VtpmTransportMessageType::VtpmTransportMessageTypeSecureSpdm,
        };
        let mut bytes = [1u8; DATA_SIZE];
        let mut writer = Writer::init(&mut bytes);
        let res = test.encode(&mut writer);
        assert_eq!(res.is_err(), false);
        let bytes = [1u8; DATA_SIZE];
        let mut reader = Reader::init(&bytes);
        let res = VtpmTransportMessageType::read(&mut reader);
        assert_eq!(res.is_none(), false);
        let mut reader = Reader::init(&[]);
        let res = VtpmTransportMessageType::read(&mut reader);
        assert_eq!(res.is_none(), true);
    }

    #[test]
    fn test_encap() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let spdm_buffer = [1u8; TEST_SPDM_BUFFER_SIZE];
        let mut buffer = [0u8; TEST_TRANSPORT_BUFFER_SIZE];
        let res = vtpm_encap.encap(&spdm_buffer, &mut buffer, false);
        assert_eq!(res.is_err(), false);
        assert_eq!(res.unwrap(), spdm_buffer.len() + VTPM_MESSAGE_HEADER_SIZE);
        let res = vtpm_encap.encap(&spdm_buffer, &mut buffer, true);
        assert_eq!(res.is_err(), false);
        assert_eq!(res.unwrap(), spdm_buffer.len() + VTPM_MESSAGE_HEADER_SIZE);
    }

    #[test]
    fn test_encap_app() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let app_message_buffer = [1u8; TEST_SPDM_BUFFER_SIZE];
        let mut app_data_buffer = [0u8; TEST_TRANSPORT_BUFFER_SIZE];
        let res = vtpm_encap.encap_app(&app_message_buffer, &mut app_data_buffer, false);
        assert_eq!(res.is_err(), false);
        assert_eq!(
            res.unwrap(),
            app_message_buffer.len() + VTPM_APP_MESSAGE_HEADER_SIZE
        );
        let res = vtpm_encap.encap_app(&app_message_buffer, &mut app_data_buffer, true);
        assert_eq!(res.is_err(), false);
        assert_eq!(
            res.unwrap(),
            app_message_buffer.len() + VTPM_APP_MESSAGE_HEADER_SIZE
        );
    }

    #[test]
    fn test_encap_invalid_buffer() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let spdm_buffer = [1u8; TEST_SPDM_BUFFER_SIZE];
        let mut buffer = [0u8; INVALID_TEST_TRANSPORT_BUFFER_SIZE];
        let res = vtpm_encap.encap(&spdm_buffer, &mut buffer, false);
        assert!(res.is_err());
        let res = vtpm_encap.encap_app(&spdm_buffer, &mut buffer, false);
        assert!(res.is_err());
        let res = vtpm_encap.encap(&spdm_buffer, &mut [], false);
        assert!(res.is_err());
        let spdm_buffer = [0u8; TEST_SPDM_BUFFER_SIZE];
        let mut buffer = [0u8; TEST_SPDM_BUFFER_SIZE];
        let res = vtpm_encap.encap(&spdm_buffer, &mut buffer, false);
        assert!(res.is_err());
    }

    #[test]
    fn test_decap() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let spdm_buffer = [0u8; TEST_SPDM_BUFFER_SIZE];
        let mut buffer = [0u8; TEST_TRANSPORT_BUFFER_SIZE];
        let res = vtpm_encap.decap(&spdm_buffer, &mut buffer);
        assert_eq!(res.unwrap().0, spdm_buffer.len() - VTPM_MESSAGE_HEADER_SIZE);
        let spdm_buffer = [0x02; TEST_SPDM_BUFFER_SIZE];
        let res = vtpm_encap.decap(&spdm_buffer, &mut buffer);
        assert_eq!(res.unwrap().0, spdm_buffer.len() - VTPM_MESSAGE_HEADER_SIZE);
    }

    #[test]
    fn test_decap_app() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let spdm_buffer = [0u8; TEST_SPDM_BUFFER_SIZE];
        let mut buffer = [0u8; TEST_TRANSPORT_BUFFER_SIZE];
        let res = vtpm_encap.decap_app(&spdm_buffer, &mut buffer);
        assert_eq!(
            res.unwrap().0,
            spdm_buffer.len() - VTPM_APP_MESSAGE_HEADER_SIZE
        );
        let spdm_buffer = [0x03; TEST_SPDM_BUFFER_SIZE];
        let res = vtpm_encap.decap_app(&spdm_buffer, &mut buffer);
        assert_eq!(
            res.unwrap().0,
            spdm_buffer.len() - VTPM_APP_MESSAGE_HEADER_SIZE
        );
    }

    #[test]
    fn test_decap_invalid_buffer() {
        let mut vtpm_encap = VtpmTransportEncap::default();
        let mut buffer = [0u8; INVALID_TEST_TRANSPORT_BUFFER_SIZE];
        let spdm_buffer = [1u8; TEST_SPDM_BUFFER_SIZE];
        let res = vtpm_encap.decap(&spdm_buffer, &mut buffer);
        assert!(res.is_err());
        let res = vtpm_encap.decap_app(&spdm_buffer, &mut buffer);
        assert!(res.is_err());
        let res = vtpm_encap.decap(&spdm_buffer, &mut []);
        assert!(res.is_err());
        let res = vtpm_encap.decap(&[], &mut []);
        assert!(res.is_err());
        let res = vtpm_encap.decap_app(&spdm_buffer, &mut []);
        assert!(res.is_err());
    }
}
