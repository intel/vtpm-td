// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::never_loop)]

use crate::{
    execute_command,
    tpm2_cmd_rsp::{
        command::Tpm2CommandHeader, getcaps::tpm2_get_caps, shutdown::tpm2_shutdown,
        startup::tpm2_startup, TPM2_CC_CREATEPRIMARY, TPM2_CC_EVICTCONTROL, TPM2_CC_NV_DEFINESPACE,
        TPM2_CC_NV_WRITE, TPM2_COMMAND_HEADER_SIZE, TPM_RC_SUCCESS, TPM_ST_SESSIONS,
    },
};
use alloc::{slice, vec::Vec};
use crypto::ek_cert::generate_ek_cert;
use global::{
    sensitive_data_cleanup, tpm::Tpm2Caps, VtpmError, VtpmResult, GLOBAL_TPM_DATA,
    VTPM_MAX_BUFFER_SIZE,
};
use ring::signature;

const TPM2_EK_ECC_SECP384R1_HANDLE: u32 = 0x81010016;
const TPM2_ALG_AES: u16 = 0x0006;
const TPM2_ALG_CFB: u16 = 0x0043;
const TPM2_RS_PW: u32 = 0x40000009;
const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ALG_SHA256: u16 = 0x000b;
const TPM2_ALG_SHA384: u16 = 0x000c;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_RH_ENDORSEMENT: u32 = 0x4000000b;
const TPM2_RH_PLATFORM: u32 = 0x4000000c;
const TPM2_RH_OWNER: u32 = 0x40000001;

const TPMA_NV_PLATFORMCREATE: u32 = 0x40000000;
const TPMA_NV_AUTHREAD: u32 = 0x40000;
const TPMA_NV_NO_DA: u32 = 0x2000000;
const TPMA_NV_PPWRITE: u32 = 0x1;
const TPMA_NV_PPREAD: u32 = 0x10000;
const TPMA_NV_OWNERREAD: u32 = 0x20000;
const TPMA_NV_WRITEDEFINE: u32 = 0x2000;

const TPM_ECC_NIST_P384: u8 = 0x04;

const TPM_PT_NV_INDEX_MAX: u32 = 0x117;
const TPM_PT_NV_BUFFER_MAX: u32 = 0x12c;
const TPM_PT_MANUFACTURER: u32 = 0x105;
const TPM_PT_VENDOR_STRING_1: u32 = 0x106;
const TPM_PT_VENDOR_STRING_2: u32 = 0x107;
const TPM_PT_VENDOR_STRING_3: u32 = 0x108;
const TPM_PT_VENDOR_STRING_4: u32 = 0x109;
const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x10b;
const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x10c;

const ECP384_PUBKEY_MAX_HALF_SIZE: usize = 48;

// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.3; Revision 2; 23 July 2020
// Section 2.2.1.5.1
const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT: u32 = 0x01c00016;
// Section 2.2.1.5.2
const TPM2_NV_INDEX_VTPM_CA_CERT_CHAIN: u32 = 0x01c00100;

#[repr(C, packed)]
struct Tpm2AuthBlock {
    pub auth: u32,
    pub rsvd: u16,
    pub continue_session: u8,
    pub bar: u16,
}

impl Tpm2AuthBlock {
    fn new(auth: u32, rsvd: u16, continue_session: u8, bar: u16) -> Self {
        Self {
            auth: auth.to_be(),
            rsvd: rsvd.to_be(),
            continue_session,
            bar: bar.to_be(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Tpm2AuthBlock as *const u8,
                core::mem::size_of::<Tpm2AuthBlock>(),
            )
        }
    }

    fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

#[repr(C, packed)]
struct Tpm2EvictControlReq {
    pub hdr: Tpm2CommandHeader,
    pub auth: u32,
    pub obj_handle: u32,
    pub authblk_len: u32,
    pub authblock: Tpm2AuthBlock,
    persistent_handle: u32,
}

impl Tpm2EvictControlReq {
    fn new(
        hdr: Tpm2CommandHeader,
        auth: u32,
        obj_handle: u32,
        authblk_len: u32,
        authblock: Tpm2AuthBlock,
        persistent_handle: u32,
    ) -> Self {
        Tpm2EvictControlReq {
            hdr,
            auth: auth.to_be(),
            obj_handle: obj_handle.to_be(),
            authblk_len: authblk_len.to_be(),
            authblock,
            persistent_handle: persistent_handle.to_be(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Tpm2EvictControlReq as *const u8,
                core::mem::size_of::<Tpm2EvictControlReq>(),
            )
        }
    }

    fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

const TPMA_OBJECT_FIXEDTPM: u32 = 0x00000002;
const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010;
const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
const TPMA_OBJECT_ADMINWITHPOLICY: u32 = 0x00000080;
const TPMA_OBJECT_RESTRICTED: u32 = 0x00010000;
const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;

///
/// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
/// Specification Version 2.3; Revision 2; 23 July 2020
/// Ek-Template for ECC NIST P384 follow B.4.6 of above spec.
///
fn tpm2_create_ek_ec384() -> VtpmResult {
    let symkeylen: u16 = 256;
    let authpolicy_len: u16 = 48;
    let tpm2_ek_handle: u32 = TPM2_EK_ECC_SECP384R1_HANDLE;
    let authpolicy: [u8; 48] = [
        0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a,
        0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4,
        0x19, 0xca, 0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3,
        0xf8, 0x0e, 0x12,
    ];

    // curve_id = TPM_ECC_NIST_P384
    let ecc_details: [u8; 8] = [0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
    let keyflags = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_ADMINWITHPOLICY
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_DECRYPT;

    // symmetric: TPM_ALG_AES, 256bit, TPM_ALG_CFB
    let symkeydata: &[u8] = &[
        TPM2_ALG_AES.to_be_bytes(),
        symkeylen.to_be_bytes(),
        TPM2_ALG_CFB.to_be_bytes(),
    ]
    .concat();

    let authblock: Tpm2AuthBlock = Tpm2AuthBlock::new(TPM2_RS_PW, 0, 0, 0);
    let mut hdr: Tpm2CommandHeader =
        Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_CREATEPRIMARY);

    let mut public: Vec<u8> = Vec::new();
    public.extend_from_slice(&TPM2_ALG_ECC.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA384.to_be_bytes());
    public.extend_from_slice(&keyflags.to_be_bytes());
    public.extend_from_slice(&authpolicy_len.to_be_bytes());
    public.extend_from_slice(&authpolicy);
    public.extend_from_slice(symkeydata);
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&ecc_details);

    let mut create_primary_req: Vec<u8> = Vec::new();
    create_primary_req.extend_from_slice(hdr.as_slice());
    create_primary_req.extend_from_slice(&TPM2_RH_ENDORSEMENT.to_be_bytes());
    create_primary_req.extend_from_slice(&Tpm2AuthBlock::size().to_be_bytes());
    create_primary_req.extend_from_slice(authblock.as_slice());
    create_primary_req.extend_from_slice(&4_u16.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&(public.len() as u16).to_be_bytes());
    create_primary_req.extend_from_slice(public.as_slice());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u16.to_be_bytes());

    let final_req_len = create_primary_req.len() as u32;
    let (left_hdr, _) = create_primary_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    left_hdr.copy_from_slice(hdr.as_slice());

    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let (rsp_size, rsp_code) = execute_command(create_primary_req.as_mut_slice(), &mut rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed of tpm2_createprimary. code = 0x{:x?}\n", rsp_code);
        return Err(VtpmError::TpmLibError);
    }

    let handle_data: &[u8] = &rsp[10..14];
    let curr_handle = u32::from_be_bytes([
        handle_data[0],
        handle_data[1],
        handle_data[2],
        handle_data[3],
    ]);

    tpm2_evictcontrol(curr_handle, tpm2_ek_handle)
}

fn tpm2_evictcontrol(curr_handle: u32, perm_handle: u32) -> VtpmResult {
    let hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(
        TPM_ST_SESSIONS,
        Tpm2EvictControlReq::size(),
        TPM2_CC_EVICTCONTROL,
    );
    let authblock: Tpm2AuthBlock = Tpm2AuthBlock::new(TPM2_RS_PW, 0, 0, 0);
    let evictcontrol_req: Tpm2EvictControlReq = Tpm2EvictControlReq::new(
        hdr,
        TPM2_RH_OWNER,
        curr_handle,
        Tpm2AuthBlock::size(),
        authblock,
        perm_handle,
    );

    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let req = evictcontrol_req.as_slice();

    let (rsp_size, rsp_code) = execute_command(req, &mut rsp, 0);
    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed of tpm2_evictcontrol. code = 0x{:x?}\n", rsp_code);
        return Err(VtpmError::TpmLibError);
    }

    Ok(())
}

/// Get the TPM EKpub key
pub fn tpm2_get_ek_pub() -> Vec<u8> {
    // TPM2_CC_ReadPublic 0x00000173
    // TPM2_EK_ECC_SECP384R1_HANDLE is 0x81010016
    let cmd_req: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x73, 0x81, 0x01, 0x00, 0x16,
    ];
    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let (rsp_size, rsp_code) = execute_command(cmd_req, &mut rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed of tpm2_readpublic. code = 0x{:x?}\n", rsp_code);
        return Vec::new();
    }

    // Output parameters
    let out_parms: &[u8] = &rsp[{ Tpm2CommandHeader::header_size() as usize }..];

    const U16_SIZE: usize = core::mem::size_of::<u16>();

    // TPM2B_PUBLIC.size field
    let size: u16 = u16::from_be_bytes(out_parms[..U16_SIZE].try_into().unwrap());

    // TPM2B_PUBLIC structure
    let tpm2b_public: &[u8] = &out_parms[..{ size as usize + U16_SIZE }];

    // skip to TPM2_PUBLIC.unique.
    // size(2) + algoType(2) + nameAlg(2) + attributes(4) + authPolicy(2+48) + symmetric(6) + scheme(4) + curveId(2)
    let mut offset = 72;
    let unique: &[u8] = &tpm2b_public[offset..];

    // log::info!("unique: {:02x?}\n", unique);

    let mut out_public: Vec<u8> = Vec::new();

    out_public.extend_from_slice(&TPM_ECC_NIST_P384.to_be_bytes());

    let x_size = u16::from_be_bytes([unique[0], unique[1]]) as usize;
    if x_size > ECP384_PUBKEY_MAX_HALF_SIZE {
        log::error!("Invalid x_size ({:?})\n", x_size);
        return Vec::new();
    }

    for _ in 0..(ECP384_PUBKEY_MAX_HALF_SIZE - x_size) {
        out_public.extend_from_slice(&0_u8.to_be_bytes());
    }
    out_public.extend_from_slice(&unique[2..2 + x_size]);
    offset = 2 + x_size;

    let y_size = u16::from_be_bytes([unique[offset], unique[offset + 1]]) as usize;
    if y_size > ECP384_PUBKEY_MAX_HALF_SIZE {
        log::error!("Invalid y_size ({:?})\n", y_size);
        return Vec::new();
    }

    for _ in 0..(ECP384_PUBKEY_MAX_HALF_SIZE - y_size) {
        out_public.extend_from_slice(&0_u8.to_be_bytes());
    }
    out_public.extend_from_slice(&unique[offset + 2..offset + 2 + y_size]);

    log::info!(
        "ecp384 public_key x_size={0:?}, y_size={1:?}\n",
        x_size,
        y_size
    );
    // log::info!("public_key {:02x?}\n", out_public);

    out_public.to_vec()
}

pub fn tpm2_write_cert_nvram(
    nvindex: u32,
    cert: &[u8],
    max_nv_index_size: u16,
    max_nv_buffer: u32,
) -> VtpmResult {
    if cert.len() > usize::from(u16::MAX) {
        log::error!("ERROR: Cert size = {:#x} too big\n", { cert.len() });
        return Err(VtpmError::InvalidParameter);
    }
    let nvindex_attrs: u32 = TPMA_NV_PLATFORMCREATE
        | TPMA_NV_AUTHREAD
        | TPMA_NV_OWNERREAD
        | TPMA_NV_PPREAD
        | TPMA_NV_PPWRITE
        | TPMA_NV_NO_DA
        | TPMA_NV_WRITEDEFINE;

    let cert_len: u16 = cert.len() as u16;

    let mut start: u16;
    let mut end: u16;
    let mut data_len: u16;
    let mut left: u16 = cert_len;
    let mut index: u32 = nvindex;
    let mut nv_space_size: u16;

    loop {
        if left == 0 {
            break;
        }

        if left > max_nv_index_size {
            nv_space_size = max_nv_index_size;
        } else {
            nv_space_size = left;
        }
        data_len = nv_space_size;

        // log::info!(
        //     "nvdefine: index={0:x?}, nv_size={1:x?}\n",
        //     index,
        //     nv_space_size
        // );
        tpm2_nvdefine_space(index, nvindex_attrs, nv_space_size as usize)?;

        start = cert_len - left;
        end = start + data_len;

        // log::info!(
        //     "  nv_write: index={0:x?}, start={1:x?}, end={2:x?}\n",
        //     index,
        //     start,
        //     end
        // );
        tpm2_nv_write(index, &cert[start as usize..end as usize], max_nv_buffer)?;

        left -= data_len;
        index += 1;
    }

    // log::info!(
    //     "INFO: Cert ({} bytes) written to the TPM NV index {:#x}\n",
    //     { cert.len() },
    //     nvindex
    // );

    Ok(())
}

fn tpm2_nvdefine_space(nvindex: u32, nvindex_attrs: u32, data_len: usize) -> VtpmResult {
    let mut hdr: Tpm2CommandHeader =
        Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_NV_DEFINESPACE);
    let authblock: Tpm2AuthBlock = Tpm2AuthBlock::new(TPM2_RS_PW, 0, 0, 0);

    let mut nvpublic: Vec<u8> = Vec::new();
    nvpublic.extend_from_slice(&nvindex.to_be_bytes());
    nvpublic.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    nvpublic.extend_from_slice(&nvindex_attrs.to_be_bytes());
    nvpublic.extend_from_slice(&0_u16.to_be_bytes());
    nvpublic.extend_from_slice(&(data_len as u16).to_be_bytes());

    let mut nv_req: Vec<u8> = Vec::new();
    nv_req.extend_from_slice(hdr.as_slice());
    nv_req.extend_from_slice(&TPM2_RH_PLATFORM.to_be_bytes());
    nv_req.extend_from_slice(&Tpm2AuthBlock::size().to_be_bytes());
    nv_req.extend_from_slice(authblock.as_slice());
    nv_req.extend_from_slice(&0_u16.to_be_bytes());
    nv_req.extend_from_slice(&(nvpublic.len() as u16).to_be_bytes());
    nv_req.extend_from_slice(nvpublic.as_slice());

    let final_req_len = nv_req.len() as u32;
    let (left_hdr, _) = nv_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    left_hdr.copy_from_slice(hdr.as_slice());

    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let (rsp_size, rsp_code) = execute_command(nv_req.as_slice(), &mut rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed of tpm2_nvdefine_space. code = {:#x}\n", rsp_code);
        return Err(VtpmError::TpmLibError);
    }

    Ok(())
}

fn tpm2_nv_write_chunk(nvindex: u32, offset: u16, data: &[u8]) -> VtpmResult {
    let mut hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_NV_WRITE);
    let authblock: Tpm2AuthBlock = Tpm2AuthBlock::new(TPM2_RS_PW, 0, 0, 0);

    let mut nv_req: Vec<u8> = Vec::with_capacity(VTPM_MAX_BUFFER_SIZE);
    nv_req.extend_from_slice(hdr.as_slice());
    nv_req.extend_from_slice(&TPM2_RH_PLATFORM.to_be_bytes());
    nv_req.extend_from_slice(&nvindex.to_be_bytes());
    nv_req.extend_from_slice(&Tpm2AuthBlock::size().to_be_bytes());
    nv_req.extend_from_slice(authblock.as_slice());
    nv_req.extend_from_slice(&(data.len() as u16).to_be_bytes());
    nv_req.extend_from_slice(data);
    nv_req.extend_from_slice(&offset.to_be_bytes());

    let final_req_len = nv_req.len() as u32;
    let (left_hdr, _) = nv_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    left_hdr.copy_from_slice(hdr.as_slice());

    let mut rsp: [u8; VTPM_MAX_BUFFER_SIZE] = [0; VTPM_MAX_BUFFER_SIZE];
    let (rsp_size, rsp_code) = execute_command(nv_req.as_slice(), &mut rsp, 0);

    if rsp_size == 0 || rsp_code != TPM_RC_SUCCESS {
        log::error!("Failed of tpm2_nv_write. code = {:#x}\n", rsp_code);
        return Err(VtpmError::TpmLibError);
    }

    Ok(())
}

fn tpm2_nv_write(nvindex: u32, data: &[u8], max_nv_buffer: u32) -> VtpmResult {
    let mut start: u16 = 0;
    let mut end: u16;
    let data_len = data.len() as u16;

    if data_len == 0 {
        return Ok(());
    }

    loop {
        end = start + max_nv_buffer as u16;
        if end > data_len {
            end = data_len;
        }

        if start >= end {
            break;
        }
        // log::info!(
        //     "    nvwrite_chunk: index={0:x?}, start={1:x?}, end={2:x?}\n",
        //     nvindex,
        //     start,
        //     end
        // );
        tpm2_nv_write_chunk(nvindex, start, &data[start as usize..end as usize])?;
        start += max_nv_buffer as u16;
    }

    Ok(())
}

fn get_tpm2_caps() -> VtpmResult {
    let tpm2_caps = tpm2_get_caps();
    if let Some(tpm2_caps) = tpm2_caps {
        let max_nv_index_size = tpm2_caps
            .get(&TPM_PT_NV_INDEX_MAX)
            .ok_or(VtpmError::TpmLibError)?;
        let max_nv_buffer_size = tpm2_caps
            .get(&TPM_PT_NV_BUFFER_MAX)
            .ok_or(VtpmError::TpmLibError)?;
        let manufacturer = tpm2_caps
            .get(&TPM_PT_MANUFACTURER)
            .ok_or(VtpmError::TpmLibError)?;
        let vendor_1 = tpm2_caps
            .get(&TPM_PT_VENDOR_STRING_1)
            .ok_or(VtpmError::TpmLibError)?;
        let vendor_2 = tpm2_caps
            .get(&TPM_PT_VENDOR_STRING_2)
            .ok_or(VtpmError::TpmLibError)?;
        let vendor_3 = tpm2_caps
            .get(&TPM_PT_VENDOR_STRING_3)
            .ok_or(VtpmError::TpmLibError)?;
        let vendor_4 = tpm2_caps
            .get(&TPM_PT_VENDOR_STRING_4)
            .ok_or(VtpmError::TpmLibError)?;
        let version_1 = tpm2_caps
            .get(&TPM_PT_FIRMWARE_VERSION_1)
            .ok_or(VtpmError::TpmLibError)?;
        let version_2 = tpm2_caps
            .get(&TPM_PT_FIRMWARE_VERSION_2)
            .ok_or(VtpmError::TpmLibError)?;

        let tpm2_caps = Tpm2Caps {
            max_nv_index_size: *max_nv_index_size,
            max_nv_buffer_size: *max_nv_buffer_size,
            manufacturer: *manufacturer,
            vendor_1: *vendor_1,
            vendor_2: *vendor_2,
            vendor_3: *vendor_3,
            vendor_4: *vendor_4,
            version_1: *version_1,
            version_2: *version_2,
        };

        GLOBAL_TPM_DATA.lock().set_tpm2_caps(&tpm2_caps);
        Ok(())
    } else {
        Err(VtpmError::TpmLibError)
    }
}

pub fn tpm2_provision_ek() -> VtpmResult {
    let mut tpm2_started = false;
    let mut ek_provisioned = false;

    loop {
        // first call TPM2_CC_Startup
        if tpm2_startup().is_err() {
            break;
        }
        tpm2_started = true;

        // get caps
        if get_tpm2_caps().is_err() {
            break;
        }

        let tpm2_caps = GLOBAL_TPM_DATA.lock().tpm2_caps().unwrap();
        let max_nv_index_size = tpm2_caps.max_nv_index_size;
        let max_nv_buffer_size = tpm2_caps.max_nv_buffer_size;

        // then Create ek_ec384
        if tpm2_create_ek_ec384().is_err() {
            break;
        }

        // get the ek_pub
        let ek_pub: Vec<u8> = tpm2_get_ek_pub();
        if ek_pub.is_empty() {
            break;
        }

        // get the ca_cert and its keypair (in pkcs8 format)
        let ca_cert = GLOBAL_TPM_DATA.lock().get_ca_cert();
        if ca_cert.is_empty() {
            break;
        }

        let mut pkcs8 = GLOBAL_TPM_DATA.lock().get_ca_cert_pkcs8();
        if pkcs8.is_empty() {
            break;
        }

        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            pkcs8.as_slice(),
            &rng,
        );
        if key_pair.is_err() {
            break;
        }
        let mut key_pair = key_pair.unwrap();

        // then generate ek-cert
        let ek_cert = generate_ek_cert(ek_pub.as_slice(), &key_pair);
        if ek_cert.is_err() {
            break;
        }
        let ek_cert = ek_cert.unwrap();

        //should clear the sensitive key data after generate_ek_cert.
        sensitive_data_cleanup(&mut key_pair);
        sensitive_data_cleanup(&mut pkcs8);
        // save ek-cert into NV
        if ek_cert.as_slice().len() > max_nv_index_size as usize {
            log::error!(
                "ek-cert size ({0:x?}) is too big to be in a single nv index({1:x?}).\n",
                ek_cert.as_slice().len(),
                max_nv_index_size
            );
            break;
        }

        if tpm2_write_cert_nvram(
            TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT,
            ek_cert.as_slice(),
            max_nv_index_size as u16,
            max_nv_buffer_size,
        )
        .is_err()
        {
            break;
        }

        // save ca-cert into NV
        if tpm2_write_cert_nvram(
            TPM2_NV_INDEX_VTPM_CA_CERT_CHAIN,
            ca_cert.as_slice(),
            max_nv_index_size as u16,
            max_nv_buffer_size,
        )
        .is_err()
        {
            break;
        }

        ek_provisioned = true;
        break;
    }

    if tpm2_started {
        tpm2_shutdown()?;
    }

    if ek_provisioned {
        Ok(())
    } else {
        log::error!("Failed to provision EK!\n");
        Err(VtpmError::EkProvisionError)
    }
}
