// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crypto::x509::Certificate;
use der::Decode;
use spin::Once;

use crate::Error;

pub static ROOT_CA: Once<Certificate> = Once::new();

pub fn set_ca(cert: &'static [u8]) -> Result<(), Error> {
    ROOT_CA
        .try_call_once(|| Certificate::from_der(cert))
        .map_err(|_| Error::InvalidRootCa)?;

    let cert = ROOT_CA.get();
    if cert.is_none() {
        return Err(Error::InvalidRootCa);
    }

    if cert
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .is_none()
    {
        return Err(Error::InvalidRootCa);
    }

    Ok(())
}
