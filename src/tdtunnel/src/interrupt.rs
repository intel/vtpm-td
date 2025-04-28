// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::sync::atomic::{AtomicU8, Ordering};
pub use td_exception::*;
use td_payload::arch::apic::{disable, enable_and_hlt};
use td_payload::interrupt_handler_template;

pub const NOTIFY_VALUE_CLEAR: u8 = 0;
pub const NOTIFY_VALUE_SET: u8 = 1;

// 32~255 are available
pub const INTERRUPT_VECTOR_WAIT_FOR_REQUEST: u8 = 32;

// Define a static atomic variable to store the notification state.
static NOTIFY_WAIT_FOR_REQUEST: AtomicU8 = AtomicU8::new(NOTIFY_VALUE_CLEAR);
const NOTIFY_VECTOR_WAIT_FOR_REQUEST: u8 = INTERRUPT_VECTOR_WAIT_FOR_REQUEST;

// Define the interrupt handler via the provided interrupt_handler_template macro.
interrupt_handler_template!(vmm_notification_wait_for_request, _stack, {
    NOTIFY_WAIT_FOR_REQUEST.store(NOTIFY_VALUE_SET, Ordering::SeqCst);
});

// Function to register the VMM notification interrupt.
pub fn register_vmm_notification_wait_for_request() {
    // Setup interrupt handler.
    unsafe {
        idt::register_handler(
            NOTIFY_VECTOR_WAIT_FOR_REQUEST,
            vmm_notification_wait_for_request,
        );
    }
}

// Function to wait for the VMM notification interrupt.
pub fn wait_for_vmm_notification_wait_for_request() {
    while NOTIFY_WAIT_FOR_REQUEST.load(Ordering::SeqCst) != NOTIFY_VALUE_SET {
        enable_and_hlt();
        if NOTIFY_WAIT_FOR_REQUEST.load(Ordering::SeqCst) == NOTIFY_VALUE_SET {
            break;
        }
    }
    disable();
    // Reset notification state.
    NOTIFY_WAIT_FOR_REQUEST.store(NOTIFY_VALUE_CLEAR, Ordering::SeqCst);
}
