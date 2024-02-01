// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::ops::DerefMut;

extern crate alloc;
use alloc::sync::Arc;
use spin::Mutex;

use global::{TdVtpmOperation, GLOBAL_SPDM_DATA};
use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::{SpdmResult, SPDM_STATUS_SEND_FAIL};

use protocol::wait_for_request;
use tdtunnel::td_tunnel::TdTunnel;

/// VtpmIoTransport implements the SpdmDeviceIo trait.
/// It accepts a mutable ref of SpdmTunnel as the stream.
pub struct VtpmIoTransport {
    pub tunnel: TdTunnel,
    pub vtpm_id: u128,
}

impl VtpmIoTransport {
    pub fn new(vtpm_id: u128) -> VtpmIoTransport {
        let tunnel = TdTunnel::default();
        Self { tunnel, vtpm_id }
    }
}

#[maybe_async::maybe_async]
impl SpdmDeviceIo for VtpmIoTransport {
    /// Send the payload out.
    /// The payload follows the format in Table 5-14/15/16
    fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let res = self.tunnel.report_status(
            &buffer.clone(),
            self.vtpm_id,
            TdVtpmOperation::Communicate as u8,
            0,
        );
        if res.is_err() {
            Err(SPDM_STATUS_SEND_FAIL)
        } else {
            Ok(())
        }
    }

    fn receive(&mut self, buffer: Arc<Mutex<&mut [u8]>>, _timeout: usize) -> Result<usize, usize> {
        let mut tmp_buf: [u8; 0x1000] = [0; 0x1000];

        let mut buffer = buffer.lock();
        let buffer = buffer.deref_mut();
        GLOBAL_SPDM_DATA.lock().clear_data();
        let res = self.tunnel.wait_for_request(buffer, self.vtpm_id);
        if res.is_err() {
            log::error!("Failed to wait_for_request!\n");
            return Err(0);
        }

        // before return the received data to rust-spdm,
        // check the validness of wait_for_request header
        let received_bytes = res.unwrap();
        tmp_buf[..received_bytes].copy_from_slice(&buffer[..received_bytes]);

        let rsp_packet =
            wait_for_request::response::Packet::new_unchecked(&tmp_buf[..received_bytes]);

        let vtpm_id = rsp_packet.vtpm_id();
        if vtpm_id == 0 {
            log::error!("Invalid vtpm_id received.\n");
            return Err(received_bytes);
        }
        if self.vtpm_id != vtpm_id {
            log::error!(
                "Receive un-matched data. {0:X?} != {1:X?}\n",
                self.vtpm_id,
                vtpm_id
            );
            return Err(received_bytes);
        }

        let operation = TdVtpmOperation::try_from(rsp_packet.operation());
        if operation.is_err() {
            GLOBAL_SPDM_DATA
                .lock()
                .set_operation(TdVtpmOperation::Invalid);
            log::error!(
                "Invalid operation received! - {:?}\n",
                rsp_packet.operation()
            );
            return Err(received_bytes);
        }

        let operation = operation.unwrap();
        if operation == TdVtpmOperation::Destroy {
            GLOBAL_SPDM_DATA
                .lock()
                .set_operation(TdVtpmOperation::Destroy);
            let _ = self.tunnel.report_status(&[0], vtpm_id, operation as u8, 0);
            log::info!("Receive Destroy event!\n");
            return Err(0);
        }

        if operation != TdVtpmOperation::Communicate {
            GLOBAL_SPDM_DATA.lock().set_operation(operation);
            log::error!(
                "Invalid operation ({:?}) received.(Expect Communicate)",
                operation
            );
            return Err(received_bytes);
        }

        let received_bytes = rsp_packet.data().len();
        buffer[..received_bytes].copy_from_slice(rsp_packet.data());

        let _ = GLOBAL_SPDM_DATA.lock().set_data(&buffer[..received_bytes]);
        GLOBAL_SPDM_DATA
            .lock()
            .set_operation(TdVtpmOperation::Communicate);

        Ok(received_bytes)
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_vtpmio_transport_send() {
        let mut vtpmio = VtpmIoTransport::new(101);
        let buffer = [1u8; 100];
        let buffer = Arc::new(&buffer[..]);
        let res = vtpmio.send(buffer);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    fn test_vtpmio_transport_recive() {
        let mut vtpmio = VtpmIoTransport::new(101);
        let mut buffer = [1u8; 100];
        let buffer = Arc::new(Mutex::new(&mut buffer[..]));
        let res = vtpmio.receive(buffer, 0);
        assert!(res.is_err());
    }

    #[test]
    fn test_flush_all() {
        let mut vtpmio = VtpmIoTransport::new(101);
        let res = vtpmio.flush_all();
        assert!(res.is_ok());
    }
}
