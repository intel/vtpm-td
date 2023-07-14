// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(test, allow(unused_imports))]
use alloc::collections::BTreeMap;
use core::alloc::Layout;
#[allow(unused, non_snake_case, non_upper_case_globals, non_camel_case_types)]
use core::{ffi::c_void, ptr::null_mut};
use lazy_static::lazy_static;
use spin::Mutex;

extern crate alloc;

#[no_mangle]
/// # Safety
///
/// This function is unsafe because of the parameter of msg
pub unsafe extern "C" fn __fw_debug_msg(msg: *const u8, len: usize) {
    let msg = unsafe {
        let r = core::slice::from_raw_parts(msg, len);
        core::str::from_utf8_unchecked(r)
    };
    log::info!("{}", msg);
}

#[no_mangle]
/// # Safety
///
/// This function is unsafe because of the parameter of buffer
pub unsafe extern "C" fn __fw_debug_buffer(buffer: *const u8, len: usize) {
    let buf = unsafe { core::slice::from_raw_parts(buffer, len) };
    log::info!("buffer {:x?}\n", buf);
}

#[no_mangle]
pub extern "C" fn __fw_abort() {
    panic!("abort called");
}

#[no_mangle]
pub extern "C" fn __fw_rdrand32() -> u32 {
    unsafe {
        let mut ret: u32 = 0;
        for _ in 0..10 {
            if core::arch::x86_64::_rdrand32_step(&mut ret) == 1 {
                return ret;
            }
        }
        panic!("Failed to obtain random data");
    }
}

lazy_static! {
    static ref MALLOC_TABLE: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
}

#[no_mangle]
/// # Safety
///
/// This function is unsafe
pub unsafe extern "C" fn __fw_malloc(size: usize) -> *mut c_void {
    let addr = alloc::alloc::alloc(Layout::from_size_align_unchecked(size, 1)) as *mut c_void;
    if addr != null_mut() {
        MALLOC_TABLE.lock().insert(addr as usize, size);
    }
    addr
}

#[no_mangle]
/// # Safety
///
/// This function is unsafe because of the parameter of ptr
pub unsafe extern "C" fn __fw_free(ptr: *mut c_void) {
    if MALLOC_TABLE.lock().contains_key(&(ptr as usize)) {
        let size = *MALLOC_TABLE.lock().get(&(ptr as usize)).unwrap();
        alloc::alloc::dealloc(ptr as *mut u8, Layout::from_size_align_unchecked(size, 1));
        MALLOC_TABLE.lock().remove_entry(&(ptr as usize));
    }
}

#[no_mangle]
/// # Safety
pub unsafe extern "C" fn __fw_realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    if MALLOC_TABLE.lock().contains_key(&(ptr as usize)) {
        let old_size = *MALLOC_TABLE.lock().get(&(ptr as usize)).unwrap();
        let ptr_new = alloc::alloc::realloc(
            ptr as *mut u8,
            Layout::from_size_align_unchecked(old_size, 1),
            new_size,
        ) as *mut c_void;

        if ptr_new != null_mut() {
            MALLOC_TABLE.lock().remove_entry(&(ptr as usize));
            MALLOC_TABLE.lock().insert(ptr_new as usize, new_size);
        }

        ptr_new
    } else {
        return null_mut();
    }
}
