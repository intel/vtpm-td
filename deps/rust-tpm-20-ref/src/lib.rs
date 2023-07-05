// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![feature(naked_functions)]

extern crate alloc;
use core::arch::asm;
#[naked]
#[no_mangle]
pub unsafe extern "C" fn ___chkstk_ms() {
    asm!(
        "push   %rcx",
        "push   %rax",
        "cmp    $0x1000,%rax",
        "lea    24(%rsp),%rcx",
        "jb     1f",
        "2:",
        "sub    $0x1000,%rcx",
        "test   %rcx,(%rcx)",
        "sub    $0x1000,%rax",
        "cmp    $0x1000,%rax",
        "ja     2b",
        "1:",
        "sub    %rax,%rcx",
        "test   %rcx,(%rcx)",
        "pop    %rax",
        "pop    %rcx",
        "ret",
        options(noreturn, att_syntax)
    );
}
