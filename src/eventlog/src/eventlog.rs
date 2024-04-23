// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use cc_measurement::log::CcEventLogReader;
use cc_measurement::CcEventHeader;
use cc_measurement::TcgPcrEventHeader;
use core::mem::size_of;
use td_payload::acpi::get_acpi_tables;
use td_shim_interface::acpi::Ccel;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub fn event_log_size(event_log: &[u8]) -> Option<usize> {
    let reader = CcEventLogReader::new(event_log)?;

    // The first event is TCG_EfiSpecIDEvent with TcgPcrEventHeader
    let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;

    for (header, _) in reader.cc_events {
        size += size_of::<CcEventHeader>() + header.event_size as usize;
    }

    Some(size)
}

fn get_event_log_from_acpi(acpi_table: &[u8]) -> Option<&'static mut [u8]> {
    if acpi_table.len() < size_of::<Ccel>() {
        return None;
    }

    let ccel = Ccel::read_from(&acpi_table[..size_of::<Ccel>()])?;

    let event_log =
        unsafe { core::slice::from_raw_parts_mut(ccel.lasa as *mut u8, ccel.laml as usize) };

    Some(event_log)
}

pub fn get_event_log() -> &'static mut [u8] {
    // Parse out ACPI tables handoff from firmware and find the event log location
    let ccel = get_acpi_tables()
        .and_then(|tables| tables.iter().find(|&&t| t[..4] == *b"CCEL"))
        .expect("Failed to find CCEL");
    get_event_log_from_acpi(ccel).expect("Fail to get event log according CCEL\n")
}
