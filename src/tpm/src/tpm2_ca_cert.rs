// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use attestation::get_quote;
use crypto::{
    ek_cert::generate_ca_cert,
    resolve::{generate_ecdsa_keypairs, ResolveError},
};
use eventlog::eventlog::{event_log_size, get_event_log};
use global::{sensitive_data_cleanup, VtpmError, VtpmResult, GLOBAL_TPM_DATA};
use ring::{
    digest,
    signature::{EcdsaKeyPair, KeyPair},
};

fn get_td_quote(data: &[u8]) -> Result<Vec<u8>, VtpmError> {
    // first calc the hash of ek_pub
    let data_hash = digest::digest(&digest::SHA384, data);

    // Generate the TD Report that contains the ek_pub hash as nonce
    let mut td_report_data = [0u8; 64];
    td_report_data[..data_hash.as_ref().len()].copy_from_slice(data_hash.as_ref());
    let td_report =
        tdx_tdcall::tdreport::tdcall_report(&td_report_data).map_err(|_| ResolveError::GetTdReport);
    if td_report.is_err() {
        log::error!("Failed to get td_report.\n");
        return Err(VtpmError::CaCertError);
    }
    let td_report = td_report.unwrap();

    // at last call get_quote
    let td_quote = get_quote(td_report.as_bytes()).map_err(|_| VtpmError::CaCertError);

    if td_quote.is_err() {
        log::error!("Failed to get td_quote.\n");
        return Err(VtpmError::CaCertError);
    }

    td_quote
}

pub fn gen_tpm2_ca_cert() -> VtpmResult {
    // create ecdsa_keypair for ca-cert
    let pkcs8 = generate_ecdsa_keypairs();
    if pkcs8.is_none() {
        log::error!("Failed to generate pkcs8.\n");
        return Err(VtpmError::CaCertError);
    }
    let mut pkcs8 = pkcs8.unwrap();

    let rng = ring::rand::SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    );

    if key_pair.is_err() {
        log::error!("Failed to generate ecdsa keypair from pkcs8.\n");
        return Err(VtpmError::CaCertError);
    }
    let mut key_pair = key_pair.unwrap();

    // get td_quote
    let td_quote = get_td_quote(key_pair.public_key().as_ref());
    if td_quote.is_err() {
        return Err(VtpmError::CaCertError);
    }
    let td_quote = td_quote.unwrap();

    // get the event_log
    let event_log = get_event_log();
    let size = event_log_size(event_log);
    if size.is_none() {
        return Err(VtpmError::CaCertError);
    }
    let size = size.unwrap();
    let event_log = &event_log[..size + 1];

    // generate ca-cert
    let ca_cert = generate_ca_cert(td_quote.as_slice(), event_log, &key_pair);
    if ca_cert.is_err() {
        return Err(VtpmError::CaCertError);
    }
    let ca_cert = ca_cert.unwrap();

    GLOBAL_TPM_DATA
        .lock()
        .set_ca_cert(ca_cert)
        .map_err(|_| VtpmError::CaCertError)?;
    GLOBAL_TPM_DATA.lock().set_ca_cert_pkcs8(pkcs8.as_ref())?;

    sensitive_data_cleanup(&mut key_pair);
    sensitive_data_cleanup(&mut pkcs8);
    Ok(())
}
