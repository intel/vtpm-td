// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

pub mod command;
pub mod response;
pub mod shutdown;
pub mod startup;

pub const TPM2_COMMAND_HEADER_SIZE: usize = 10;
pub const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_SU_CLEAR: u16 = 0u16;
pub const TPM_SU_STATE: u16 = 1u16;
pub const TPM_RC_SUCCESS: u32 = 0;

/// TPM Shutdown
pub const TPM_CC_SHUTDOWN: u32 = 0x145;
pub const TPM_STARTUP_CMD: [u8; 12] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
];
pub const TPM_SHUTDOWN_CMD: [u8; 12] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00,
];
