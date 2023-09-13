// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::collections::BTreeMap;
use global::VTPM_MAX_BUFFER_SIZE;

use crate::execute_command;

use super::TPM_RC_SUCCESS;

const TPM_CAP_TPM_PROPERTIES: u32 = 6;

fn read_u32_from_bytes(bytes: &[u8], be: bool) -> u32 {
    let mut buf: [u8; 4] = [0; 4];
    buf.copy_from_slice(bytes);
    let mut val: u32 = 0;
    if be {
        val = u32::from_be_bytes(buf);
    } else {
        val = u32::from_le_bytes(buf);
    }

    val
}

pub fn tpm2_get_caps() -> Option<BTreeMap<u32, u32>> {
    let req: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x7f,
    ];
    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let (rsp_size, rsp_code) = execute_command(req, &mut rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed to tpm2_get_caps\n");
        return None;
    }

    let mut properties: BTreeMap<u32, u32> = BTreeMap::new();

    // skip the rsp header
    let mut offset: usize = 10;
    // skip the more_data
    offset += 1;
    // check capability. It should be TPM_CAP_TPM_PROPERTIES(0x6)
    let capability: u32 = read_u32_from_bytes(&rsp[offset..offset + 4], true);
    if capability != TPM_CAP_TPM_PROPERTIES {
        return None;
    }

    //properties count
    offset += 4;
    let prop_count: u32 = read_u32_from_bytes(&rsp[offset..offset + 4], true);
    if prop_count == 0 {
        return None;
    }

    // walk thru the properties
    offset += 4;
    if rsp_size as usize - offset != (prop_count * 8) as usize {
        return None;
    }

    for _i in 0..prop_count {
        let prop: u32 = read_u32_from_bytes(&rsp[offset..offset + 4], true);
        offset += 4;
        let val: u32 = read_u32_from_bytes(&rsp[offset..offset + 4], true);
        properties.insert(prop, val);
        offset += 4;
    }

    Some(properties)
}
