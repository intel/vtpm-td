// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use crate::{sensitive_data_cleanup, VtpmError, VtpmResult, TPM2_NV_SIZE};
use crate::{PKCS8_DOCUMENT_MAX_LEN, VTPM_CA_CERT_MAX_SIZE};
use alloc::vec::Vec;

#[derive(Clone, Copy)]
pub struct GlobalTpmData {
    pub provisioned: bool,
    pub last_tpm_cmd_code: Option<u32>,
    pub last_tpm_rsp_code: Option<u32>,
    tpm_active: bool,
    nv_mem: [u8; TPM2_NV_SIZE],
    // ca_cert related data
    ca_cert: [u8; VTPM_CA_CERT_MAX_SIZE],
    ca_cert_size: usize,
    ca_cert_pkcs8: [u8; PKCS8_DOCUMENT_MAX_LEN],
    ca_cert_pkcs8_size: usize,
}

impl Default for GlobalTpmData {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalTpmData {
    pub fn new() -> GlobalTpmData {
        Self {
            provisioned: false,
            last_tpm_cmd_code: None,
            last_tpm_rsp_code: None,
            tpm_active: false,
            nv_mem: [0xff; TPM2_NV_SIZE],
            ca_cert: [0; VTPM_CA_CERT_MAX_SIZE],
            ca_cert_size: 0,
            ca_cert_pkcs8: [0; PKCS8_DOCUMENT_MAX_LEN],
            ca_cert_pkcs8_size: 0,
        }
    }

    pub fn set_tpm_active(&mut self, active: bool) {
        self.tpm_active = active;
    }

    pub fn tpm_active(&self) -> bool {
        self.tpm_active
    }

    pub fn tpm2_nv_mem(&self) -> &[u8] {
        &self.nv_mem
    }

    pub fn set_nv_mem(&mut self, nv_mem: &[u8]) -> Result<usize, VtpmError> {
        if nv_mem.len() != self.nv_mem.len() {
            return Err(VtpmError::InvalidParameter);
        }

        self.nv_mem.copy_from_slice(nv_mem);
        Ok(nv_mem.len())
    }

    pub fn clean_nv_mem(&mut self) {
        sensitive_data_cleanup(&mut self.nv_mem);
    }

    pub fn set_ca_cert(&mut self, ca_cert: Vec<u8>) -> Result<usize, VtpmError> {
        if self.ca_cert.len() < ca_cert.len() {
            return Err(VtpmError::OutOfResource);
        }
        self.ca_cert_size = ca_cert.len();
        self.ca_cert[..self.ca_cert_size].copy_from_slice(&ca_cert.as_slice());
        Ok(ca_cert.len())
    }

    pub fn get_ca_cert(self) -> Vec<u8> {
        let mut ca_cert: Vec<u8> = Vec::new();
        if self.ca_cert_size > 0 {
            ca_cert.extend_from_slice(&self.ca_cert[..self.ca_cert_size]);
        }
        ca_cert
    }

    pub fn set_ca_cert_pkcs8(&mut self, ca_cert_pkcs8: &[u8]) -> VtpmResult<usize> {
        if self.ca_cert_pkcs8.len() < ca_cert_pkcs8.len() {
            Err(VtpmError::OutOfResource)
        } else {
            self.ca_cert_pkcs8_size = ca_cert_pkcs8.len();
            self.ca_cert_pkcs8[..self.ca_cert_pkcs8_size].copy_from_slice(ca_cert_pkcs8);
            Ok(self.ca_cert_pkcs8_size)
        }
    }

    pub fn clean_ca_cert_pkcs8(&mut self) {
        sensitive_data_cleanup(&mut self.ca_cert_pkcs8);
        self.ca_cert_pkcs8_size = 0;
    }

    pub fn get_ca_cert_pkcs8(&self) -> Vec<u8> {
        let mut pkcs8: Vec<u8> = Vec::new();

        if self.ca_cert_pkcs8_size > 0 {
            pkcs8.extend_from_slice(&self.ca_cert_pkcs8[..self.ca_cert_pkcs8_size]);
        }

        pkcs8
    }

    pub fn ca_cert_ready(&self) -> bool {
        if self.ca_cert_size > 0 && self.ca_cert_pkcs8_size > 0 {
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.clean_nv_mem();
        self.last_tpm_cmd_code = None;
        self.last_tpm_rsp_code = None;
        self.tpm_active = false;
    }
}
