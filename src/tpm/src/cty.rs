// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(non_camel_case_types)]

pub use arch::*;
pub use os::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64",))]
mod arch {
    pub type c_char = super::c_schar;
    pub type c_int = i32;
    pub type c_uint = u32;
}

#[cfg(any(windows,))]
mod os {
    pub type c_long = i32;
    pub type c_ulong = u32;
}
#[cfg(not(any(windows,)))]
mod os {
    #[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
    pub type c_long = i32;
    #[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
    pub type c_ulong = u32;
    #[cfg(all(target_pointer_width = "64"))]
    pub type c_long = i64;
    #[cfg(all(target_pointer_width = "64"))]
    pub type c_ulong = u64;
}

pub type int8_t = i8;
pub type int16_t = i16;
pub type int32_t = i32;
pub type int64_t = i64;

pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type uint64_t = u64;

pub type c_schar = i8;
pub type c_short = i16;
pub type c_longlong = i64;

pub type c_uchar = u8;
pub type c_ushort = u16;
pub type c_ulonglong = u64;

pub type c_float = f32;
pub type c_double = f64;

pub type intmax_t = i64;
pub type uintmax_t = u64;

pub type size_t = usize;
pub type ptrdiff_t = isize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ssize_t = isize;

pub type c_void = core::ffi::c_void;
