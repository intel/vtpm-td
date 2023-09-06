// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use der::asn1::ObjectIdentifier;
use der::{Any, Encodable, Tag};
use global::VTPM_MAX_BUFFER_SIZE;
use ring::signature::{EcdsaKeyPair, KeyPair};
use ring::{digest, rand::SystemRandom};

use crate::resolve::{EXTENDED_KEY_USAGE, EXTNID_VTPMTD_EVENT_LOG, EXTNID_VTPMTD_QUOTE};
use crate::x509::{self, Extension};
use crate::{
    resolve::{ResolveError, ID_EC_PUBKEY_OID, SECP384R1_OID, VTPMTD_EXTENDED_KEY_USAGE},
    x509::{AlgorithmIdentifier, X509Error},
};

pub fn generate_ek_cert_chain(
    td_quote: &[u8],
    event_log: &[u8],
    ek_pub: &[u8],
    ecdsa_keypair: &EcdsaKeyPair,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    // first generate ca-cert
    let ca_cert = generate_ca_cert(td_quote, ecdsa_keypair)?;
    let ca_cert_hash = digest::digest(&digest::SHA384, ca_cert.as_slice());

    // then generate ek-cert
    let ek_cert = generate_ek_cert(event_log, ek_pub, ecdsa_keypair)?;

    // last combine 2 certs into cert-chain
    let mut cert_chain: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(VTPM_MAX_BUFFER_SIZE);
    let cert_chain_len: u16 = (4 + 48 + ca_cert.len() + ek_cert.len()) as u16;
    cert_chain.extend_from_slice(&cert_chain_len.to_le_bytes());
    cert_chain.extend_from_slice(&0_u16.to_le_bytes());
    cert_chain.extend_from_slice(ca_cert_hash.as_ref());
    cert_chain.extend_from_slice(ca_cert.as_slice());
    cert_chain.extend_from_slice(ek_cert.as_slice());

    assert!(cert_chain.len() == cert_chain_len as usize);

    Ok(cert_chain)
}

fn generate_ca_cert(
    td_quote: &[u8],
    ecdsa_keypair: &EcdsaKeyPair,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = ecdsa_keypair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![VTPMTD_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let x509_certificate =
        x509::CertificateBuilder::new(algorithm, algorithm, ecdsa_keypair.public_key().as_ref())?
            // 1970-01-01T00:00:00Z
            .set_not_before(core::time::Duration::new(0, 0))?
            // 9999-12-31T23:59:59Z
            .set_not_after(core::time::Duration::new(253402300799, 0))?
            .add_extension(Extension::new(
                EXTENDED_KEY_USAGE,
                Some(false),
                Some(eku.as_slice()),
            )?)?
            .add_extension(Extension::new(
                EXTNID_VTPMTD_QUOTE,
                Some(false),
                Some(td_quote),
            )?)?
            .sign(&mut sig_buf, signer)?
            .build();

    x509_certificate
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}

fn generate_ek_cert(
    event_log: &[u8],
    ek_pub: &[u8],
    ecdsa_keypair: &EcdsaKeyPair,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = ecdsa_keypair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![VTPMTD_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let x509_certificate = x509::CertificateBuilder::new(algorithm, algorithm, ek_pub)?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))?
        .add_extension(Extension::new(
            EXTENDED_KEY_USAGE,
            Some(false),
            Some(eku.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTNID_VTPMTD_EVENT_LOG,
            Some(false),
            Some(event_log),
        )?)?
        .sign(&mut sig_buf, signer)?
        .build();

    x509_certificate
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}
