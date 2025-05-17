// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::xor_unchecked;
use crate::KEY_SIZE;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hmac::HmacKey;
use fastcrypto::{
    aes::{
        Aes256Gcm as ExternalAes256Gcm, AesKey, AuthenticatedCipher, GenericByteArray,
        InitializationVector,
    },
    error::FastCryptoResult,
    traits::ToFromBytes,
};
use typenum::U16;

pub struct Aes256Gcm;

impl Aes256Gcm {
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .encrypt_authenticated(&Self::iv(), aad, msg)
    }

    pub fn decrypt(
        ciphertext: &[u8],
        aad: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> FastCryptoResult<Vec<u8>> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .decrypt_authenticated(&Self::iv(), aad, ciphertext)
    }
}

impl Aes256Gcm {
    /// We use a fixed IV. This is okay because the key is never reused.
    const IV: [u8; 16] = [
        138, 55, 153, 253, 198, 46, 121, 219, 160, 128, 89, 7, 214, 156, 148, 220,
    ];

    /// Get the fixed IV.
    fn iv() -> InitializationVector<U16> {
        GenericByteArray::from_bytes(&Self::IV).expect("fixed value")
    }
}

/// Authenticated encryption using CTR mode with HMAC-SHA3-256 as a PRF.
/// 1. Derive an encryption key, <i>k<sub>1</sub> = <b>hmac</b>(key, 1)</i>.
/// 2. Chunk the message into blocks of 32 bytes, <i>m = m<sub>1</sub> || ... || m<sub>n</sub></i>.
/// 3. Let the ciphertext be defined by <i>c = c<sub>1</sub> || ... || c<sub>n</sub></i> where <i>c<sub>i</sub> = m<sub>i</sub> ⊕ <b>hmac</b>(k<sub>1</sub>, i)</i>.
/// 4. Compute a MAC over the AAD and the ciphertext, <i>mac = <b>hmac</b>(k<sub>2</sub>, aad || c) where k<sub>2</sub> = <b>hmac</b>(key, 2)</i>.
/// 5. Return <i>mac || c</i>.
pub struct Hmac256Ctr;

impl Hmac256Ctr {
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let ciphertext = encrypt_in_ctr_mode(key, msg);
        let mac = compute_mac(key, aad, &ciphertext);
        (ciphertext, mac)
    }

    pub fn decrypt(
        ciphertext: &[u8],
        mac: &[u8; 32],
        aad: &[u8],
        key: &[u8; 32],
    ) -> FastCryptoResult<Vec<u8>> {
        let actual_mac = compute_mac(key, aad, ciphertext);
        if mac != &actual_mac {
            return Err(FastCryptoError::GeneralError("Invalid MAC".to_string()));
        }
        let msg = encrypt_in_ctr_mode(key, ciphertext);
        Ok(msg)
    }
}

/// Encrypts the message in CTR mode using hmac_sha3_256 as a PRF.
fn encrypt_in_ctr_mode(key: &[u8; KEY_SIZE], msg: &[u8]) -> Vec<u8> {
    // Derive encryption key
    let encryption_key = hmac_sha3_256(key, &[1]);
    msg.chunks(KEY_SIZE)
        .enumerate()
        .flat_map(|(i, ci)| xor_unchecked(ci, &hmac_sha3_256(&encryption_key, &to_bytes(i))))
        .collect()
}

fn compute_mac(key: &[u8; KEY_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; KEY_SIZE] {
    // Derive MAC key
    let mac_key = hmac_sha3_256(key, &[2]);

    // The length of the aad may vary, so add the length as a prefix to ensure uniqueness of the input.
    hmac_sha3_256(&mac_key, &[&to_bytes(aad.len()), aad, ciphertext].concat())
}

/// Convenience function for hmac_sha3_256.
fn hmac_sha3_256(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; KEY_SIZE] {
    fastcrypto::hmac::hmac_sha3_256(
        &HmacKey::from_bytes(key).expect("Never fails for 32 byte input"),
        data,
    )
    .digest
}

/// Convenience function for converting a usize to a byte array.
fn to_bytes(n: usize) -> Vec<u8> {
    bcs::to_bytes(&(n as u64)).expect("Never fails")
}

#[cfg(test)]
mod tests {
    use crate::dem::{Aes256Gcm, Hmac256Ctr};
    use crate::{utils::generate_random_bytes, KEY_SIZE};
    use rand::thread_rng;

    const TEST_MSG: &[u8] = b"The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.";
    const TEST_AAD: &[u8] = b"Mark Twain";

    #[test]
    fn test_aes_gcm() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let ciphertext = Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key);
        let decrypted = Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_fail() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        let ciphertext = Aes256Gcm::encrypt(msg, aad, &key);

        assert_eq!(
            msg,
            Aes256Gcm::decrypt(&ciphertext, b"something", &key)
                .unwrap()
                .as_slice()
        );
        assert!(Aes256Gcm::decrypt(&ciphertext, b"something else", &key).is_err());
    }

    #[test]
    fn regression_test_aes_gcm() {
        let key: [u8; KEY_SIZE] =
            hex::decode("43041389faab1f789fa56722b1def4c3ec6da22675e9bd8ad7329cd931bc840a")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext: Vec<u8> = hex::decode("a3a5c857ee27937f43ccfb42b41ca2155c9a4a77a8e54af35f78a78ff102206142d1be22dfc39a6374463255934ae640adceeffb17e56b9190d8c5f6456e9e7ff1c4eaa45114b640b407efd371f26b1f7d7e48bd86d742a01c0ad7dbe18b86df188e27cb029978b7fd243d9a63bdabd76aa478").unwrap();
        assert_eq!(
            TEST_MSG,
            Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        assert_eq!(Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key), ciphertext);
    }

    #[test]
    fn test_hmac_ctr() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let (ciphertext, mac) = Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key);
        let decrypted = Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    #[test]
    fn test_hmac_ctr_fail() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        let (ciphertext, mac) = Hmac256Ctr::encrypt(msg, aad, &key);
        assert_eq!(
            msg,
            Hmac256Ctr::decrypt(&ciphertext, &mac, b"something", &key)
                .unwrap()
                .as_slice()
        );
        assert!(Hmac256Ctr::decrypt(&ciphertext, &mac, b"something else", &key).is_err());
    }

    #[test]
    fn regression_test_hmac_ctr() {
        let key: [u8; KEY_SIZE] =
            hex::decode("5bfdfd7c814903f1311bebacfffa3c001cbeb1cbb3275baa9aafe21fadd9f396")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext: Vec<u8> = hex::decode("b0c4eee6fbd97a2fb86bbd1e0dafa47d2ce5c9e8975a50c2d9eae02ebede8fee6b6434e68584be475b89089fce4c451cbd4c0d6e00dbcae1241abaf237df2eccdd86b890d35e4e8ae9418386012891d8413483d64179ce1d7fe69ad25d546495df54a1").unwrap();
        let mac: [u8; KEY_SIZE] =
            hex::decode("5de3ffdd9d7a258e651ebdba7d80839df2e19ea40cd35b6e1b06375181a0c2f2")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            TEST_MSG,
            Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key),
            (ciphertext, mac)
        );
    }
}
