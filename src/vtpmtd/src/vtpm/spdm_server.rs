// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::cmp::{self, Ordering};
use core::convert::{TryFrom, TryInto};
use core::panic;

use ::crypto::resolve::{
    generate_ecdsa_keypairs, get_cert_from_certchain, verify_peer_cert, TDVF_EXTENDED_KEY_USAGE,
};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use global::{TdVtpmOperation, VtpmError, GLOBAL_SPDM_DATA, GLOBAL_TPM_DATA};
use log::info;
use ring::pkcs8;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use spdmlib::common::session::SpdmSessionState;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::crypto::dhe::generate_key_pair;
use spdmlib::crypto::{cert_operation, SpdmCertOperation};
use spdmlib::error::{SpdmStatus, SPDM_STATUS_INVALID_CERT};
use spdmlib::protocol::SpdmVersion;
use tpm::execute_command;
use tpm::tpm2_ca_cert::gen_tpm2_ca_cert;
use x86::halt;

use super::spdm_connection::SpdmConnection;
use crate::vtpm::spdm_cbs::{
    register_spdm_cert_operation, register_spdm_secure_app_message_handler,
};
use crate::vtpm::spdm_connection;
use crate::vtpm::spdm_connection::SpdmConnectionStatus;
use ::spdm::crypto_callback::ASYM_SIGN_IMPL;
use lazy_static::lazy_static;
use protocol::report_status::TdVtpmReportStatus;
use protocol::wait_for_request;
use spdmlib::{crypto, error::SpdmResult, responder::ResponderContext};
use spin::Mutex;
use tdtunnel::interrupt::register_vmm_notification_wait_for_request;
use tdtunnel::td_tunnel::{TdTunnel, TdVtpmEvent};

#[no_mangle]
pub extern "C" fn start_spdm_server() {
    log::info!("Startup TdSpdmServer ...\n");

    let mut buffer: [u8; 0x1000] = [0; 0x1000];
    let mut td_tunnel = TdTunnel::default();

    register_vmm_notification_wait_for_request();
    if !register_spdm_secure_app_message_handler() {
        panic!("Failed to call register_spdm_secure_app_message_handler\n");
    }

    if !spdmlib::secret::asym_sign::register(ASYM_SIGN_IMPL.clone()) {
        panic!("Failed to call spdmlib::crypto::asym_sign::register\n");
    }

    register_spdm_cert_operation();

    if gen_tpm2_ca_cert().is_err() {
        log::error!("Failed to generate tpm2 ca_cert!\n");
        unsafe { halt() };
    }

    loop {
        let received_bytes = td_tunnel.wait_for_request(&mut buffer, 0);
        if received_bytes.is_err() {
            log::error!("Failed to wait_for_request!\n");
            continue;
        }

        let received_bytes = received_bytes.unwrap();
        let rsp_packet =
            wait_for_request::response::Packet::new_unchecked(&buffer[..received_bytes]);
        let vtpm_id = rsp_packet.vtpm_id();
        if vtpm_id == 0 {
            log::error!("Invalid vtpm_id received!\n");
            continue;
        }

        let operation = TdVtpmOperation::try_from(rsp_packet.operation());
        if operation.is_err() {
            log::error!("Invalid operation received!\n");
            let _ = td_tunnel.report_status(
                &[],
                vtpm_id,
                rsp_packet.operation(),
                TdVtpmReportStatus::InvalidOperation as u8,
            );
            continue;
        }

        let operation = operation.unwrap();
        if operation != TdVtpmOperation::Create {
            log::error!("Invalid operation received (expect Create)!\n");
            let _ = td_tunnel.report_status(
                &[],
                vtpm_id,
                operation as u8,
                TdVtpmReportStatus::InvalidOperation as u8,
            );
            continue;
        }

        let _ = td_tunnel.report_status(
            &[],
            vtpm_id,
            operation as u8,
            TdVtpmReportStatus::Success as u8,
        );

        GLOBAL_SPDM_DATA.lock().clear();
        GLOBAL_SPDM_DATA.lock().set_vtpm_id(vtpm_id);
        GLOBAL_SPDM_DATA
            .lock()
            .set_operation(TdVtpmOperation::Create);
        GLOBAL_SPDM_DATA.lock().valid = true;

        let mut spdm_connection: SpdmConnection = SpdmConnection::new(vtpm_id);
        let res = spdm_connection.run();
        if let Err(res) = res {
            break;
        }

        let operation = GLOBAL_SPDM_DATA.lock().operation();
        if let Ok(operation) = operation {
            if operation == TdVtpmOperation::Destroy {
                log::info!("Wait for another Create event.\n");
                GLOBAL_TPM_DATA.lock().clear();
                GLOBAL_SPDM_DATA.lock().clear();
                continue;
            }
        }

        log::error!("Error!!! Quit the main loop.\n");
        break;
    }

    unsafe { halt() };
}
