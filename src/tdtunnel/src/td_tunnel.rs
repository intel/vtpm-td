// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use global::{TdVtpmOperation, VtpmError, VtpmResult, VTPM_MAX_BUFFER_SIZE};
use tdx_tdcall::tdx::tdvmcall_service;

use interrupt::{wait_for_vmm_notification_wait_for_request, INTERRUPT_VECTOR_WAIT_FOR_REQUEST};
use protocol::report_status::TdVtpmReportStatus;
use td_payload::mm::dma::{alloc_dma_pages, free_dma_pages};

use crate::interrupt;

/// allocate one page
fn alloc<'a>(size: usize) -> Option<&'a mut [u8]> {
    if size > VTPM_MAX_BUFFER_SIZE {
        return None;
    }
    unsafe {
        alloc_dma_pages(1)
            .map(|address| core::slice::from_raw_parts_mut(address as *const u8 as *mut u8, size))
    }
}

/// free a page
fn free(target: &[u8]) {
    unsafe { free_dma_pages(target.as_ptr() as usize, 1) }
}

///
/// TdTunnel does the actual read/write data via TdVmcall<vtpm.service>
///
/// It calls wait_for_request to read data.
/// It calls report_status to send data
///
#[derive(Default, Debug)]
pub struct TdTunnel {}

impl TdTunnel {
    /// wait_for_request Section 5.1.7
    /// This function is called to wait_for_request from VMM.
    /// The received data in @buffer. Its size is the returned value.
    /// The received data is in the format of @wait_for_request
    pub fn wait_for_request(&mut self, buffer: &mut [u8], vtpm_id: u128) -> VtpmResult<usize> {
        use protocol::{service, wait_for_request, SERVICE_VTPMTD_GUID};

        let cmd_buffer = alloc(VTPM_MAX_BUFFER_SIZE).expect("Allocate cmd_buffer failed.");
        let rsp_buffer = alloc(VTPM_MAX_BUFFER_SIZE).expect("Allocate rsp_buffer failed.");

        // build wait_for_request command
        let service_header_len = service::command::HEADER_LEN;
        let cmd_size = wait_for_request::command::build_command_header(
            &mut cmd_buffer[service_header_len..],
            vtpm_id,
        )?;
        let total_cmd_size = cmd_size + service_header_len;
        let _ = service::command::build_command_header(
            SERVICE_VTPMTD_GUID,
            &mut cmd_buffer[0..total_cmd_size],
        )?;

        // build wait_for_reqeust response
        let _ = wait_for_request::response::build_response_header(
            &mut rsp_buffer[service_header_len..],
            vtpm_id,
        )?;
        let _ = service::response::build_response_header(SERVICE_VTPMTD_GUID, rsp_buffer)?;

        // now call tdvmcall
        let res = tdvmcall_service(
            cmd_buffer,
            rsp_buffer,
            INTERRUPT_VECTOR_WAIT_FOR_REQUEST as u64,
            0,
        );
        if res.is_err() {
            log::error!("Err in tdvmcall_service(wait_for_request). {:?}\n", res);
            free(cmd_buffer);
            free(rsp_buffer);
            return Err(VtpmError::VmmError);
        }

        wait_for_vmm_notification_wait_for_request();
        // log::info!("Wakeup by interrupt.\n");

        let mut tmp_buffer: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
        tmp_buffer[..].copy_from_slice(rsp_buffer);
        let rsp_packet = service::response::Packet::new_unchecked(tmp_buffer);
        if rsp_packet.status() != 0 {
            log::error!("Status of wait_for_request_rsp = {}\n", rsp_packet.status());
            free(cmd_buffer);
            free(rsp_buffer);
            return Err(VtpmError::VmmError);
        }

        let data = rsp_packet.data();
        let len = data.len();
        buffer[0..len].copy_from_slice(data);
        log::info!("Data received {0} bytes.\n", len);
        // log::info!("{:02x?}\n", &buffer[..len]);
        // log::info!("\n");
        free(cmd_buffer);
        free(rsp_buffer);
        Ok(len)
    }

    /// send report_status
    pub fn report_status(
        &mut self,
        buffer: &[u8],
        vtpm_id: u128,
        operation: u8,
        status: u8,
    ) -> VtpmResult<usize> {
        use protocol::{report_status, service, SERVICE_VTPMTD_GUID};

        let cmd_buffer = alloc(VTPM_MAX_BUFFER_SIZE).expect("Allocate cmd_buffer failed.");
        let rsp_buffer = alloc(VTPM_MAX_BUFFER_SIZE).expect("Allocate rsp_buffer failed.");

        let service_header_len = service::command::HEADER_LEN;
        let buffer_len = buffer.len();

        // build command
        let report_status_cmd_len = report_status::command::build_command(
            vtpm_id,
            operation, // communicate
            status,
            buffer,
            &mut cmd_buffer[service_header_len..],
        )?;
        let nlen = service::command::build_command_header_and_size(
            SERVICE_VTPMTD_GUID,
            &mut cmd_buffer[..(report_status_cmd_len + service_header_len)],
        )?;

        log::info!("Send data {0} bytes.\n", nlen);
        // log::info!("{:02x?}\n", &cmd_buffer[..nlen]);
        // log::info!("\n");

        // build response
        let _ =
            report_status::response::build_response_header(&mut rsp_buffer[service_header_len..]);
        let _ = service::response::build_response_header(SERVICE_VTPMTD_GUID, rsp_buffer)
            .map(|_| VtpmError::Unknown);

        // call tdvmcall
        let res = tdvmcall_service(cmd_buffer, rsp_buffer, 0, 0);
        if res.is_err() {
            free(cmd_buffer);
            free(rsp_buffer);

            return Err(VtpmError::VmmError);
        }

        free(cmd_buffer);
        free(rsp_buffer);

        Ok(buffer_len)
    }
}

#[derive(Clone, Copy)]
pub struct TdVtpmEvent {
    pub vtpm_id: u128,
    pub operation: TdVtpmOperation,
    pub data: [u8; 0x1000],
    pub size: usize,
    pub status: TdVtpmReportStatus,
}

impl TdVtpmEvent {
    pub fn new(
        vtpm_id: u128,
        operation: TdVtpmOperation,
        data: &[u8],
        size: usize,
        status: TdVtpmReportStatus,
    ) -> Self {
        let mut buf: [u8; 0x1000] = [0; 0x1000];
        buf[0..size].copy_from_slice(data);
        Self {
            vtpm_id,
            operation,
            data: buf,
            size,
            status,
        }
    }

    pub fn get_operation(self) -> TdVtpmOperation {
        self.operation
    }

    pub fn get_tdvm_id(self) -> u128 {
        self.vtpm_id
    }
}
