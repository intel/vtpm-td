// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(unused_imports))]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
extern crate alloc;

pub mod ghci;
pub mod td_quote;
