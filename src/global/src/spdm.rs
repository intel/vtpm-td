// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::{sensitive_data_cleanup, VtpmError, VtpmResult};
use crate::{TdVtpmOperation, PKCS8_DOCUMENT_MAX_LEN, VTPM_MAX_BUFFER_SIZE};

pub struct GlobalSpdmData {
    pub valid: bool,
    vtpm_id: u128,
    operation: TdVtpmOperation,
    data: [u8; VTPM_MAX_BUFFER_SIZE],
    data_size: usize,
    pkcs8: [u8; PKCS8_DOCUMENT_MAX_LEN],
    pcks8_size: usize,
}

impl GlobalSpdmData {
    pub fn new() -> GlobalSpdmData {
        Self {
            valid: false,
            vtpm_id: 0,
            operation: TdVtpmOperation::None,
            data: [0; VTPM_MAX_BUFFER_SIZE],
            data_size: 0,
            pkcs8: [0; PKCS8_DOCUMENT_MAX_LEN],
            pcks8_size: 0,
        }
    }

    pub fn clear_data(&mut self) {
        self.data_size = 0;
        self.operation = TdVtpmOperation::None;
    }

    pub fn clear(&mut self) {
        self.valid = false;
        self.vtpm_id = 0;
        self.operation = TdVtpmOperation::None;
        self.data_size = 0;
        self.pcks8_size = 0;
    }

    pub fn set_vtpm_id(&mut self, vtpm_id: u128) {
        self.vtpm_id = vtpm_id;
    }

    pub fn vtpm_id(&self) -> VtpmResult<u128> {
        if self.valid {
            Ok(self.vtpm_id)
        } else {
            Err(VtpmError::InvalidParameter)
        }
    }

    pub fn set_operation(&mut self, operation: TdVtpmOperation) {
        self.operation = operation
    }

    pub fn operation(&self) -> VtpmResult<TdVtpmOperation> {
        if self.valid {
            Ok(self.operation)
        } else {
            Err(VtpmError::InvalidParameter)
        }
    }

    pub fn set_data(&mut self, data: &[u8]) -> VtpmResult<usize> {
        if self.data.len() < data.len() {
            Err(VtpmError::OutOfResource)
        } else {
            self.data_size = data.len();
            self.data[..self.data_size].copy_from_slice(data);
            Ok(self.data_size)
        }
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.valid {
            Some(&self.data[..self.data_size])
        } else {
            None
        }
    }

    pub fn set_pkcs8(&mut self, pkcs8: &[u8]) -> VtpmResult<usize> {
        if self.pkcs8.len() < pkcs8.len() {
            Err(VtpmError::OutOfResource)
        } else {
            self.pcks8_size = pkcs8.len();
            self.pkcs8[..self.pcks8_size].copy_from_slice(pkcs8);
            Ok(self.pcks8_size)
        }
    }

    pub fn clean_pkcs8(&mut self) {
        sensitive_data_cleanup(&mut self.pkcs8);
    }

    pub fn pkcs8(&self) -> Option<&[u8]> {
        if self.valid {
            Some(&self.pkcs8[..self.pcks8_size])
        } else {
            None
        }
    }
}
