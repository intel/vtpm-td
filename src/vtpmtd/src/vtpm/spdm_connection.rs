// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use ::crypto::resolve::{generate_certificate, generate_ecdsa_keypairs};
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use eventlog::eventlog::{event_log_size, get_event_log};
use global::{sensitive_data_cleanup, TdVtpmOperation, GLOBAL_SPDM_DATA, GLOBAL_TPM_DATA};
use ring::{
    digest::digest,
    pkcs8::{self, Document},
    signature::{self, EcdsaKeyPair},
};
use spdm::{vtpm_io_transport::VtpmIoTransport, vtpm_transport_encap::VtpmTransportEncap};
use spdmlib::{
    common::{
        self,
        session::{self, SpdmSessionState},
        SpdmConfigInfo, SpdmDeviceIo, SpdmOpaqueSupport, SpdmProvisionInfo,
        DMTF_SECURE_SPDM_VERSION_10, DMTF_SECURE_SPDM_VERSION_11, ST1,
    },
    config::{self, *},
    crypto,
    error::SpdmResult,
    message::{
        vendor, RegistryOrStandardsBodyID, SpdmKeyUpdateOperation, SpdmMeasurementOperation,
    },
    protocol::{
        SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertChainData, SpdmDheAlgo,
        SpdmDmtfMeasurementStructure, SpdmKeyScheduleAlgo, SpdmMeasurementBlockStructure,
        SpdmMeasurementHashAlgo, SpdmMeasurementRecordStructure, SpdmMeasurementSpecification,
        SpdmMeasurementSummaryHashType, SpdmReqAsymAlgo, SpdmRequestCapabilityFlags,
        SpdmResponseCapabilityFlags, SpdmVersion, SHA384_DIGEST_SIZE,
    },
    responder::{self, ResponderContext},
};
use tpm::{start_tpm, terminate_tpm};

fn make_config_info() -> common::SpdmConfigInfo {
    common::SpdmConfigInfo {
        spdm_version: [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
        ],
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
            | SpdmResponseCapabilityFlags::ENCAP_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP, // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        heartbeat_period: config::HEARTBEAT_PERIOD,
        secure_spdm_version: [DMTF_SECURE_SPDM_VERSION_10, DMTF_SECURE_SPDM_VERSION_11],
        ..Default::default()
    }
}

fn make_provision_info() -> Option<common::SpdmProvisionInfo> {
    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let event_log = get_event_log();
    let size = event_log_size(event_log)?;
    let event_log = &event_log[..size + 1];

    let mut pkcs8 = generate_ecdsa_keypairs().expect("Failed to generate ecdsa keypair.\n");
    GLOBAL_SPDM_DATA.lock().set_pkcs8(pkcs8.as_ref());

    let mut key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.as_ref(),
    );

    if key_pair.is_err() {
        return None;
    }

    let mut key_pair = key_pair.unwrap();
    let cert = generate_certificate(&key_pair, event_log);
    if cert.is_err() {
        return None;
    }
    let cert = cert.unwrap();

    let mut cert_data = SpdmCertChainData {
        data_size: cert.len() as u16,
        ..Default::default()
    };
    cert_data.data[..cert_data.data_size as usize].copy_from_slice(cert.as_ref());

    // log::info!("Cert_data size: {:?}\n", cert_data.data_size);

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: [Some(cert_data), None, None, None, None, None, None, None],
        my_cert_chain: [None, None, None, None, None, None, None, None],
        peer_root_cert_data: None,
    };

    sensitive_data_cleanup(&mut key_pair);
    sensitive_data_cleanup(&mut pkcs8);
    Some(provision_info)
}

#[derive(Clone, PartialEq, Debug, Copy)]
pub enum SpdmConnectionStatus {
    /// Not started
    NotStarted,

    /// Handshakeing with a Spdm requester
    Handshaking,

    /// Session is established to a Spdm requester
    Established,
}

pub struct SpdmConnection {
    pub vtpm_id: u128,
    pub status: SpdmConnectionStatus, // spdm connection status
    pub session_id: u32,
    pub session_state: SpdmSessionState,
}

impl SpdmConnection {
    pub fn new(vtpm_id: u128) -> SpdmConnection {
        Self {
            vtpm_id: vtpm_id,
            status: SpdmConnectionStatus::NotStarted,
            session_id: 0,
            session_state: SpdmSessionState::SpdmSessionNotStarted,
        }
    }

    fn shutdown_tpm(&self) {
        if GLOBAL_TPM_DATA.lock().tpm_active() {
            terminate_tpm();
            GLOBAL_TPM_DATA.lock().set_tpm_active(false);
        }
        GLOBAL_SPDM_DATA.lock().clean_pkcs8();
    }

    fn startup_tpm(&self) {
        if !GLOBAL_TPM_DATA.lock().tpm_active() {
            start_tpm();
            GLOBAL_TPM_DATA.lock().set_tpm_active(true);
        }
        GLOBAL_SPDM_DATA.lock().clean_pkcs8();
    }

    pub fn run(&mut self) {
        let mut device_io = VtpmIoTransport::new(self.vtpm_id);
        let mut vtpm_transport_encap = VtpmTransportEncap::default();

        let provision_info = make_provision_info();
        if provision_info.is_none() {
            log::error!("Failed to make provison info\n");
            return;
        }

        let mut context: ResponderContext = responder::ResponderContext::new(
            &mut device_io,
            &mut vtpm_transport_encap,
            make_config_info(),
            provision_info.unwrap(),
        );

        loop {
            let mut do_reset_context: bool = true;
            let mut do_shutdown_tpm = false;
            let mut do_startup_tpm = false;

            let mut sess_id: u32 = 0;
            let mut current_session_state: SpdmSessionState =
                SpdmSessionState::SpdmSessionNotStarted;

            let res = context.process_message(ST1, &[]);
            if let Ok(res) = res {
                if res {
                    // SPDM message handled correctly
                    // Check the SPDM status
                    let sessions_status = context.common.get_session_status();
                    // Currently there is only one session can be established in a ResponderContext
                    // So the returned sessions_status shall have only one working session.
                    if sessions_status.is_empty() {
                        log::error!("There shall be at least one session returned.");
                    } else {
                        (sess_id, current_session_state) = sessions_status[0];
                        do_reset_context = false;
                    }
                } else {
                    // Received unknown spdm command
                    log::error!("Received unknown SPDM command\n");
                }
            } else {
                log::error!("Unexpected result of context.process_message.\n");
            }

            if !do_reset_context {
                // status machine
                match self.session_state {
                    SpdmSessionState::SpdmSessionNotStarted => {
                        if current_session_state == SpdmSessionState::SpdmSessionHandshaking {
                            self.status = SpdmConnectionStatus::Handshaking;
                            self.session_state = SpdmSessionState::SpdmSessionHandshaking;
                            self.session_id = 0;
                        } else if current_session_state == SpdmSessionState::SpdmSessionNotStarted {
                            // do nothing
                        } else {
                            log::error!(
                                "Unexpected state - 1! {0:x?} : {1:x?}",
                                self.session_state,
                                current_session_state
                            );
                            do_reset_context = true;
                        }
                    }
                    SpdmSessionState::SpdmSessionHandshaking => {
                        if current_session_state == SpdmSessionState::SpdmSessionHandshaking {
                            // still in handshakeing. so do nothing
                        } else if current_session_state == SpdmSessionState::SpdmSessionEstablished
                        {
                            // session is established.
                            self.status = SpdmConnectionStatus::Established;
                            self.session_state = SpdmSessionState::SpdmSessionEstablished;
                            self.session_id = sess_id;

                            do_startup_tpm = true;
                        } else {
                            log::error!(
                                "Unexpected state - 2! {0:?} : {1:?}",
                                self.session_state,
                                current_session_state
                            );
                            do_reset_context = true;
                        }
                    }
                    SpdmSessionState::SpdmSessionEstablished => {
                        if current_session_state == SpdmSessionState::SpdmSessionEstablished {
                            // do nothing
                        } else if current_session_state == SpdmSessionState::SpdmSessionNotStarted {
                            // the session is closed.
                            self.status = SpdmConnectionStatus::NotStarted;
                            self.session_state = current_session_state;
                            self.session_id = 0;

                            do_shutdown_tpm = true;
                        } else if current_session_state == SpdmSessionState::Unknown(0) {
                            // the session is closed.
                            self.status = SpdmConnectionStatus::NotStarted;
                            self.session_state = SpdmSessionState::SpdmSessionNotStarted;
                            self.session_id = 0;

                            do_shutdown_tpm = true;
                        } else {
                            log::error!(
                                "Unexpected state - 3! {0:?} : {1:?}",
                                self.session_state,
                                current_session_state
                            );
                            do_reset_context = true;
                        }
                    }
                    SpdmSessionState::Unknown(_) => {
                        log::error!("Unexpected session state!");
                        do_reset_context = true;
                    }
                }
            }

            if do_startup_tpm {
                log::info!("Startup the tpm\n");
                self.startup_tpm();
            } else if do_shutdown_tpm {
                log::info!("Shutdown the tpm\n");
                self.shutdown_tpm();
            } else if do_reset_context {
                log::info!("Reset spdm-session\n");
                context.common.reset_context();
                self.session_state = SpdmSessionState::SpdmSessionNotStarted;
                self.shutdown_tpm();
            }

            if do_reset_context || do_shutdown_tpm {
                // prepare for the next incoming SPDM
                let provision_info = make_provision_info();
                if provision_info.is_none() {
                    panic!("Failed to make provision_info for rust-spdm!");
                }
                context.common.provision_info = provision_info.unwrap();
            }

            let operation = GLOBAL_SPDM_DATA.lock().operation();
            if operation.is_ok() && operation.unwrap() == TdVtpmOperation::Destroy {
                log::info!("Destroy event received. Quit the main loop.\n");
                break;
            }
        }
    }
}
