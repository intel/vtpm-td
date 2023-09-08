// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::{TPM_RC_SUCCESS, TPM_STARTUP_CMD};
use crate::execute_command;
use global::{VtpmError, VtpmResult, VTPM_MAX_BUFFER_SIZE};

pub fn tpm2_startup() -> VtpmResult {
    let mut tpm_rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];

    let (rsp_size, rsp_code) = execute_command(&TPM_STARTUP_CMD, &mut tpm_rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("tpm2_startup failed with rsp_code 0x{:x?}\n", rsp_code);
        return Err(VtpmError::TpmLibError);
    }

    Ok(())
}
