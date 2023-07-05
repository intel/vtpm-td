#![no_std]
#![feature(naked_functions)]

extern crate alloc;
use core::arch::asm;
#[no_mangle]
pub extern "C" fn __fw_debug_msg(msg: *const u8, len: usize) {
    let msg = unsafe {
        let r = core::slice::from_raw_parts(msg, len);
        core::str::from_utf8_unchecked(r)
    };
    log::info!("{}", msg);
}

#[no_mangle]
pub extern "C" fn __fw_debug_buffer(buffer: *const u8, len: usize) {
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

#[no_mangle]
pub unsafe extern "C" fn __fw_malloc(s: usize) -> *mut u8 {
    use alloc::alloc::Layout;
    alloc::alloc::alloc(Layout::from_size_align(s, 1).unwrap())
}

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
