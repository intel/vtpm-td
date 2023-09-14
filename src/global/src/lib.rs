// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]

use zeroize::Zeroize;

pub mod spdm;
pub mod tpm;

pub const VTPM_MAX_BUFFER_SIZE: usize = 0x1000;
pub const TPM2_NV_SIZE: usize = 0x4000;
pub const PKCS8_DOCUMENT_MAX_LEN: usize = 185;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{spdm::GlobalSpdmData, tpm::GlobalTpmData};

lazy_static! {
    pub static ref GLOBAL_SPDM_DATA: Mutex<GlobalSpdmData> = Mutex::new(GlobalSpdmData::new());
}

lazy_static! {
    pub static ref GLOBAL_TPM_DATA: Mutex<GlobalTpmData> = Mutex::new(GlobalTpmData::new());
}

#[derive(Debug, PartialEq, Eq)]
pub enum VtpmError {
    /// Buffer too small
    Truncated,

    /// Out of Resource
    OutOfResource,

    /// Vmm error
    VmmError,

    /// Spdm error
    SpdmError,

    /// PipeError
    PipeError,

    /// Invalid param
    InvalidParameter,

    ///
    ExceedMaxConnection,

    ///
    ExceedMaxTpmInstanceCount,

    ///
    TpmLibError,

    ///
    EkProvisionError,

    ///
    CaCertError,

    Unknown,
}
pub type VtpmResult<T = ()> = core::result::Result<T, VtpmError>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TdVtpmOperation {
    None = 0,
    Communicate = 1,
    Create = 2,
    Destroy = 3,
    Migration = 4,
    Invalid = 0xff,
}

impl TryFrom<u8> for TdVtpmOperation {
    type Error = VtpmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TdVtpmOperation::None),
            1 => Ok(TdVtpmOperation::Communicate),
            2 => Ok(TdVtpmOperation::Create),
            3 => Ok(TdVtpmOperation::Destroy),
            4 => Ok(TdVtpmOperation::Migration),
            _ => Err(VtpmError::InvalidParameter),
        }
    }
}

pub fn sensitive_data_cleanup<T: Sized>(t: &mut T) {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(t as *mut T as u64 as *mut u8, core::mem::size_of::<T>())
    };
    bytes.zeroize();
}

#[cfg(test)]
mod test {
    use super::*;

    const MAX_VTPM_OPERATION_ENUM: u8 = 4;

    #[test]
    fn test_try_form() {
        let num = [0, 1, 2, 3, 4, 5, 6];
        for i in num {
            let res = TdVtpmOperation::try_from(i);
            if i > MAX_VTPM_OPERATION_ENUM {
                assert_eq!(res.unwrap_err(), VtpmError::InvalidParameter);
            } else {
                assert!(res.is_ok())
            }
        }
    }
}
