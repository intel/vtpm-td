// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::sync::atomic::{AtomicU8, Ordering};
use td_payload::{
    arch::{
        apic::{disable, enable_and_hlt},
        idt::register,
    },
    interrupt_handler_template,
};

pub static NOTIFIER: AtomicU8 = AtomicU8::new(0);
const NOTIFY_VECTOR: u8 = 0x51;
pub const NOTIFY_VALUE: u8 = 1;
interrupt_handler_template!(vmm_notification, _stack, {
    NOTIFIER.store(NOTIFY_VALUE, Ordering::SeqCst);
});

pub fn set_vmm_notification() {
    // Setup interrupt handler
    register(NOTIFY_VECTOR, vmm_notification);

    // Setup event notifier
    if tdx_tdcall::tdx::tdvmcall_setup_event_notify(NOTIFY_VECTOR as u64).is_err() {
        panic!("Fail to setup VMM event notifier\n");
    }
}

pub fn wait_for_vmm_notification() {
    while NOTIFIER.load(Ordering::SeqCst) == 0 {
        // Halt to wait until interrupt comming
        enable_and_hlt();
        if NOTIFIER.load(Ordering::SeqCst) == 1 {
            break;
        }
    }

    // Reset the value of NOTIFIER
    NOTIFIER.store(0, Ordering::SeqCst);
    disable();
}
