// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports))]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#![allow(unused)]

extern crate alloc;

#[allow(
    unused,
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    improper_ctypes
)]
#[allow(unused)]
mod vtpm;

use core::ffi::c_void;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use td_layout::runtime::*;
use td_uefi_pi::hob::{check_hob_integrity, dump_hob, get_system_memory_size_below_4gb};

#[cfg(not(test))]
#[no_mangle]
#[cfg(target_os = "none")]
pub extern "C" fn _start(hob: u64, payload: u64) -> ! {
    use td_payload::arch;
    use td_payload::mm::end_of_ram;
    use td_payload::mm::layout::*;

    const STACK_SIZE: usize = 0x10_0000; // 1M
    const HEAP_SIZE: usize = 0x20_0000; // 2M
    const PT_SIZE: usize = 0x8_0000;

    extern "C" {
        fn start_spdm_server();
    }

    let layout = RuntimeLayout {
        heap_size: HEAP_SIZE,
        stack_size: STACK_SIZE,
        page_table_size: PT_SIZE,
        dma_size: DEFAULT_DMA_SIZE,
        #[cfg(feature = "cet-shstk")]
        shadow_stack_size: DEFAULT_SHADOW_STACK_SIZE,
    };

    #[cfg(feature = "test_stack_size")]
    {
        td_benchmark::StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0xd000);
    }

    let _ = td_logger::init();
    log::info!("vtpm-td is startup\n");

    #[cfg(any(feature = "test_stack_size", feature = "test_heap_size"))]
    {
        log::info!("td_benchmark enabled.\n");
    }

    arch::init::pre_init(hob, &layout);

    // Run the global constructors
    init(payload);

    arch::init::init(&layout, start_spdm_server);

    panic!("deadloop");
}

#[cfg(target_os = "none")]
fn init(payload: u64) {
    use td_loader::elf;

    let elf = unsafe {
        core::slice::from_raw_parts(
            payload as *const u8,
            td_layout::runtime::exec::PAYLOAD_SIZE as usize,
        )
    };

    // Call the init functions (contains C++ constructions of global variables)
    if let Some(range) = elf::parse_init_array_section(elf) {
        let mut init_start = payload as usize + range.start;
        let init_end = payload as usize + range.end;
        while init_start < init_end {
            let init_fn = init_start as *const fn();
            unsafe { (*init_fn)() };
            init_start += 8;
        }
    }
}
