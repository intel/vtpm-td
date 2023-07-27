// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::panic;
use global::GLOBAL_SPDM_DATA;
use spdmlib::protocol::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct, SPDM_MAX_ASYM_KEY_SIZE,
};
use spdmlib::secret::SpdmSecretAsymSign;

pub static ASYM_SIGN_IMPL: SpdmSecretAsymSign = SpdmSecretAsymSign { sign_cb: asym_sign };

fn asym_sign(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo(&ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING, data)
        }
        _ => {
            panic!(
                "Not supported asym_algo! - {0:?}:{1:?}\n",
                base_hash_algo, base_asym_algo
            );
        }
    }
}

fn sign_ecdsa_asym_algo(
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    assert!(algorithm == &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING);

    let binding = GLOBAL_SPDM_DATA.lock();
    let pkcs8 = binding.pkcs8()?;

    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, pkcs8);
    if key_pair.is_err() {
        return None;
    }
    let key_pair = key_pair.unwrap();

    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data);
    if signature.is_err() {
        return None;
    }

    let binding = signature.unwrap();
    let signature = binding.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_KEY_SIZE] = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}

#[cfg(test)]
mod test {

    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{self, EcdsaKeyPair};
    #[test]
    fn test_asym_sign() {
        let mut data = [2u8; 0x100];
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        GLOBAL_SPDM_DATA.lock().valid = true;
        let rand = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rand)
                .map_err(|_| 0);

        assert_eq!(pkcs8_bytes.is_err(), false);
        let pkcs8 = pkcs8_bytes.unwrap();
        let res = GLOBAL_SPDM_DATA.lock().set_pkcs8(pkcs8.as_ref());
        assert_eq!(res.is_err(), false);

        let res = asym_sign(base_hash_algo, base_asym_algo, &mut data);
        assert_eq!(res.is_none(), false);
    }

    #[test]
    #[should_panic]
    fn test_sign_ecdsa_asym_algo_other_algo() {
        let mut data = [2u8; 96];
        sign_ecdsa_asym_algo(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &mut data);
    }

    #[test]
    #[should_panic]
    fn test_asym_sign_other_algo() {
        let mut data = [2u8; 0x100];
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        asym_sign(base_hash_algo, base_asym_algo, &mut data);
    }
}
