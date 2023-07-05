// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

pub const DEFAULT_VERSION: u8 = 0;
pub const COMMAND_REPORT_STATUS: u8 = 0x2;

pub mod command;
pub mod response;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TdVtpmReportStatus {
    Success = 0,
    InvalidParameter = 1,
    Unsupported = 2,
    OutOfResource = 3,
    Reserved = 4,
    NetworkError = 5,
    SecureSessionError = 6,
    MutualAttestationError = 7,
    MigPolicyError = 8,
    InvalidOperation = 9,
    UserTdAlreadyExist = 10,
    UserTdNotFound = 11,
    ExceedMaxConnection = 12,
    ExceedMaxTpmInstance = 13,
    InternalError = 0xff,
}
