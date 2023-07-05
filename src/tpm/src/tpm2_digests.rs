// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use global::{VtpmError, VtpmResult};

pub const TPM2_HASH_ALG_ID_SHA256: u16 = 0xb;
pub const TPM2_HASH_ALG_ID_SHA384: u16 = 0xc;
pub const TPM2_HASH_ALG_ID_SHA512: u16 = 0xd;

pub const TPM2_SUPPORTED_HASH_COUNT: usize = 4;
pub const MAX_TPM2_DIGESTS_SIZE: usize = (MAX_TPM2_HASH_SIZE + 2) * TPM2_SUPPORTED_HASH_COUNT;

pub const TPM2_SHA256_SIZE: usize = 32;
pub const TPM2_SHA384_SIZE: usize = 48;
pub const TPM2_SHA512_SIZE: usize = 64;
pub const MAX_TPM2_HASH_SIZE: usize = TPM2_SHA512_SIZE;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2Digest {
    pub alg_id: u16,
    pub hash_size: usize,
    pub total_size: usize,
    pub hash: [u8; MAX_TPM2_HASH_SIZE],
}

impl Tpm2Digest {
    pub fn new(alg_id: u16, value: &[u8]) -> Option<Tpm2Digest> {
        let hash_size = Tpm2Digest::get_hash_size(alg_id)?;
        if value.len() != hash_size {
            return None;
        }

        let mut hash: [u8; MAX_TPM2_HASH_SIZE] = [0; MAX_TPM2_HASH_SIZE];
        hash[..hash_size].copy_from_slice(value);

        let total_size = hash_size + 2;

        Some(Self {
            alg_id,
            hash_size,
            total_size,
            hash,
        })
    }

    fn get_hash_size(alg_id: u16) -> Option<usize> {
        match alg_id {
            TPM2_HASH_ALG_ID_SHA256 => Some(TPM2_SHA256_SIZE),
            TPM2_HASH_ALG_ID_SHA384 => Some(TPM2_SHA384_SIZE),
            TPM2_HASH_ALG_ID_SHA512 => Some(TPM2_SHA512_SIZE),
            _ => None,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Tpm2Digest> {
        let alg_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let hash_size = Tpm2Digest::get_hash_size(alg_id)?;
        if bytes.len() < hash_size + 2 {
            return None;
        }

        Tpm2Digest::new(alg_id, &bytes[2..hash_size + 2])
    }

    pub fn to_bytes(&self, out_buffer: &mut [u8]) -> Option<usize> {
        if out_buffer.len() < self.total_size {
            return None;
        }

        out_buffer[..2].copy_from_slice(&self.alg_id.to_be_bytes());
        out_buffer[2..self.hash_size + 2].copy_from_slice(&self.hash[..self.hash_size]);

        Some(self.total_size)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Tpm2Digests {
    digests: Vec<Tpm2Digest>,
    pub total_size: usize,
    pub digests_count: usize,
}

impl Tpm2Digests {
    pub fn new() -> Tpm2Digests {
        Self {
            digests: Vec::new(),
            total_size: 0,
            digests_count: 0,
        }
    }

    pub fn push_digest(&mut self, digest: &Tpm2Digest) -> VtpmResult {
        let hash_size = Tpm2Digest::get_hash_size(digest.alg_id);
        if hash_size.is_none() {
            return Err(VtpmError::InvalidParameter);
        }

        self.digests.push(digest.clone());
        self.total_size += digest.total_size;
        self.digests_count += 1;

        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Tpm2Digests> {
        let size = bytes.len();
        let mut offset: usize = 0;
        let mut digests = Tpm2Digests::default();

        loop {
            let dig = Tpm2Digest::from_bytes(&bytes[offset..])?;
            offset = dig.total_size;
            let _ = digests.push_digest(&dig);

            if offset >= size {
                break;
            }
        }

        Some(digests)
    }

    pub fn to_bytes(&self, out_buffer: &mut [u8]) -> Option<usize> {
        let mut offset: usize = 0;
        let out_buffer_size = out_buffer.len();
        let mut tmp_buffer: [u8; MAX_TPM2_HASH_SIZE + 2] = [0; MAX_TPM2_HASH_SIZE + 2];

        if out_buffer_size < self.total_size {
            return None;
        }

        for digest in &self.digests {
            if digest.total_size > out_buffer_size - offset {
                return None;
            }
            let size = digest.to_bytes(&mut tmp_buffer)?;
            out_buffer[offset..offset + digest.total_size].copy_from_slice(&tmp_buffer[..size]);
            offset += digest.total_size;
        }

        Some(offset)
    }
}

impl Default for Tpm2Digests {
    fn default() -> Self {
        Self::new()
    }
}
