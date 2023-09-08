// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::td_report::verify_td_report;
use super::x509::{self, Extension, X509Error};
use super::x509::{AlgorithmIdentifier, ExtendedKeyUsage, Extensions};
use crate::x509::Certificate;
use alloc::vec;
use der::asn1::ObjectIdentifier;
use der::{Any, Decodable, Encodable, Tag};
use ring::digest;
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};

use tdx_tdcall::tdreport::TD_REPORT_SIZE;

pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
pub const VTPMTD_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.1");
pub const EXTNID_VTPMTD_REPORT: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.4");
pub const EXTNID_VTPMTD_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.2");
pub const EXTNID_VTPMTD_EVENT_LOG: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.3");

pub const TDVF_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.1");
pub const EXTNID_TDVF_REPORT: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.4");
pub const EXTNID_TDVF_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.2");

pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.1");
pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.2");

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

#[derive(Debug)]
pub enum ResolveError {
    GenerateKey,
    GenerateCertificate(X509Error),
    SignCertificate,
    GetTdReport,
    GetTdQuote,
}

impl From<X509Error> for ResolveError {
    fn from(e: X509Error) -> Self {
        ResolveError::GenerateCertificate(e)
    }
}

pub fn generate_ecdsa_keypairs() -> Option<Document> {
    let rand = SystemRandom::new();
    let pkcs8_bytes =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rand)
            .map_err(|_| ResolveError::GenerateKey);

    if let Ok(pkcs8_bytes) = pkcs8_bytes {
        Some(pkcs8_bytes)
    } else {
        None
    }
}

fn generate_td_report(public_key: &[u8]) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let public_key_hash = digest::digest(&digest::SHA384, public_key);

    // Generate the TD Report that contains the public key hash as nonce
    let mut td_report_data = [0u8; 64];
    td_report_data[..public_key_hash.as_ref().len()].copy_from_slice(public_key_hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&td_report_data)
        .map_err(|_| ResolveError::GetTdReport)?;
    Ok(td_report.as_bytes().to_vec())
}

pub fn generate_certificate(
    key_pair: &EcdsaKeyPair,
    event_log: &[u8],
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    // This is a closure for signing certificate used by x.509 certificate builder
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = key_pair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate tdreport
    let td_report = generate_td_report(key_pair.public_key().as_ref())?;

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };
    let eku = vec![VTPMTD_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let x509_certificate =
        x509::CertificateBuilder::new(algorithm, algorithm, key_pair.public_key().as_ref())?
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
                EXTNID_VTPMTD_REPORT,
                Some(false),
                Some(td_report.as_slice()),
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

// Here is a workaround to cleanup the structures that contain sensitive
// data, since some of the structure defined by ring do not implement the
// trait 'drop' to zero the content
// See https://github.com/briansmith/ring/issues/15
pub fn get_cert_from_certchain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    let mut offset = 0usize;
    let mut this_index = 0isize;
    let cert_chain_size = cert_chain.len();
    loop {
        if cert_chain[offset..].len() < 4 || offset > cert_chain.len() {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if cert_chain[offset] != 0x30 || cert_chain[offset + 1] != 0x82 {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        let this_cert_len =
            ((cert_chain[offset + 2] as usize) << 8) + (cert_chain[offset + 3] as usize) + 4;
        if this_cert_len > cert_chain_size - offset {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if this_index == index {
            // return this one
            return Ok((offset, offset + this_cert_len));
        }
        this_index += 1;
        if (offset + this_cert_len == cert_chain_size) && (index == -1) {
            // return the last one
            return Ok((offset, offset + this_cert_len));
        }
        offset += this_cert_len;
    }
}

pub fn parse_extensions<'a>(extensions: &'a Extensions) -> Option<&'a [u8]> {
    let mut has_tdvf_usage = false;
    let mut td_report = None;

    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes()).ok();
                if eku.is_none() {
                    log::error!("Cannot parse EXTENDED_KEY_USAGE\n");
                    break;
                }

                if eku.unwrap().contains(&TDVF_EXTENDED_KEY_USAGE) {
                    has_tdvf_usage = true;
                }
            }
        } else if extn.extn_id == EXTNID_TDVF_REPORT {
            td_report = extn.extn_value.map(|v| v.as_bytes());
        }
    }

    if !has_tdvf_usage {
        log::error!("no tdvf_usage\n");
        return None;
    }

    if let Some(td_report) = td_report {
        Some(td_report)
    } else {
        log::error!("no td_report\n");
        None
    }
}

pub fn verify_peer_cert(cert_chain: &[u8], td_report_buf: &mut [u8]) -> SpdmResult {
    if td_report_buf.len() != TD_REPORT_SIZE {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let (start, end) = get_cert_from_certchain(cert_chain, 0)?;

    let cert =
        Certificate::from_der(&cert_chain[start..end]).map_err(|_| SPDM_STATUS_INVALID_CERT)?;

    let extensions = cert.tbs_certificate.extensions.as_ref();

    if extensions.is_none() {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let td_report = parse_extensions(extensions.unwrap());
    if td_report.is_none() {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let td_report = td_report.unwrap();

    // verify td_report
    verify_td_report(td_report)?;

    td_report_buf.copy_from_slice(td_report);

    Ok(())
}
