// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use paste::paste;

use core::sync::atomic::{AtomicU8, Ordering};
pub use td_exception::*;
use td_payload::interrupt_handler_template;
use tdx_tdcall::tdx::tdvmcall_halt;

pub const NOTIFY_VALUE_CLEAR: u8 = 0;
pub const NOTIFY_VALUE_SET: u8 = 1;

#[macro_export]
macro_rules! register_interrupt {
    ($name:ident, $notifiy_vector:expr) => {

        paste! {
            const [<NOTIFY_VECTOR_ $name:upper>]: u8 = $notifiy_vector;
            static [<NOTIFY_ $name:upper>]: AtomicU8 = AtomicU8::new(NOTIFY_VALUE_CLEAR);
            interrupt_handler_template!([<vmm_notification_ $name:lower>], _stack, {
                [<NOTIFY_ $name:upper>].store(NOTIFY_VALUE_SET, Ordering::SeqCst);
            });

            pub fn [<register_vmm_notification_ $name:lower>]() {
                // log::info!("Calling {:?}", stringify!([<register_vmm_notification_ $name:lower>]));
                // #[cfg(test)]
                // return;

                // Setup interrupt handler
                unsafe {
                    idt::register_handler([<NOTIFY_VECTOR_ $name:upper>], [<vmm_notification_ $name:lower>]);
                }
            }

            pub fn [<wait_for_vmm_notification_ $name:lower>]() {
                // #[cfg(test)]
                // return;

                // log::info!("Calling {:?}", stringify!([<wait_for_vmm_notification_ $name:lower>]));

                while([<NOTIFY_ $name:upper>].load(Ordering::SeqCst) != NOTIFY_VALUE_SET){
                    x86_64::instructions::interrupts::enable();
                    tdvmcall_halt();
                    if ([<NOTIFY_ $name:upper>].load(Ordering::SeqCst) == NOTIFY_VALUE_SET){
                        break;
                    }
                }
                x86_64::instructions::interrupts::disable();

                // log::debug!("============== WOKE UP ============\n");
                // log::debug!("NOTIFY_WAIT_FOR_REQUEST:{:?}\n", NOTIFY_WAIT_FOR_REQUEST);
                // log::debug!("NOTIFY_REPORT_STATUS:{:?}\n", NOTIFY_REPORT_STATUS);
                // log::debug!("NOTIFY_SPDM_PCI_DOE:{:?}\n", NOTIFY_SPDM_PCI_DOE);
                // log::debug!("NOTIFY_SHUTDOWN:{:?}\n", NOTIFY_SHUTDOWN);
                // log::debug!("NOTIFY_SERVICE_QUERY:{:?}\n", NOTIFY_SERVICE_QUERY);
                [<NOTIFY_ $name:upper>].store(NOTIFY_VALUE_CLEAR, Ordering::SeqCst);
            }
        }
    };
}

// 32~255 are available
pub const INTERRUPT_VECTOR_WAIT_FOR_REQUEST: u8 = 32;

register_interrupt!(wait_for_request, INTERRUPT_VECTOR_WAIT_FOR_REQUEST);
