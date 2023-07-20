// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::{sensitive_data_cleanup, VtpmError, TPM2_NV_SIZE};

pub struct GlobalTpmData {
    pub provisioned: bool,
    pub last_tpm_cmd_code: Option<u32>,
    pub last_tpm_rsp_code: Option<u32>,
    tpm_active: bool,
    nv_mem: [u8; TPM2_NV_SIZE],
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
}

#[cfg(test)]
mod test {
    use super::*;

    const INVALID_NV_SIZE: usize = 0x2000;

    #[test]
    fn test_function() {
        let mut globaltpmdata = GlobalTpmData::default();
        assert_eq!(globaltpmdata.tpm_active, globaltpmdata.tpm_active());
        let active = true;
        globaltpmdata.set_tpm_active(active);
        assert_eq!(globaltpmdata.tpm_active, globaltpmdata.tpm_active());
        assert_eq!(globaltpmdata.tpm_active, active);
        assert_eq!(globaltpmdata.tpm_active(), active);
        assert_eq!(globaltpmdata.nv_mem, globaltpmdata.tpm2_nv_mem());
        let invalid_nv = [1; INVALID_NV_SIZE];
        let res = globaltpmdata.set_nv_mem(&invalid_nv);
        assert!(res.is_err());

        let nv_mem_data: [u8; TPM2_NV_SIZE] = [1; TPM2_NV_SIZE];
        let res = globaltpmdata.set_nv_mem(&nv_mem_data);
        assert_eq!(res.unwrap(), TPM2_NV_SIZE);
        assert_eq!(globaltpmdata.nv_mem, nv_mem_data);
        assert_eq!(globaltpmdata.tpm2_nv_mem(), nv_mem_data);
        globaltpmdata.clean_nv_mem();
        let zerodata: [u8; TPM2_NV_SIZE] = [0; TPM2_NV_SIZE];
        assert_eq!(globaltpmdata.nv_mem, globaltpmdata.tpm2_nv_mem());
        assert_eq!(globaltpmdata.nv_mem, zerodata);
        assert_eq!(globaltpmdata.tpm2_nv_mem(), zerodata);
    }
}
