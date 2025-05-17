// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of a the Boneh-Franklin Identity-based encryption scheme from https://eprint.iacr.org/2001/090 over the BLS12-381 curve construction.
//! It enables a symmetric key to be derived from the identity + the public key of a user and used to encrypt a fixed size message of length [KEY_LENGTH].

use crate::utils::xor;
use crate::{DST_POP, KEY_SIZE};
use fastcrypto::error::FastCryptoError::{GeneralError, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{G1Element, G2Element, GTElement, Scalar};
use fastcrypto::groups::{GroupElement, HashToGroupElement, Pairing, Scalar as GenericScalar};
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::AllowedRng;
use fastcrypto::traits::ToFromBytes;
use sui_types::base_types::ObjectID;

pub type MasterKey = Scalar;
pub type PublicKey = G2Element;
pub type UserSecretKey = G1Element;
pub type Nonce = G2Element;
pub type Plaintext = [u8; KEY_SIZE];
pub type Ciphertext = [u8; KEY_SIZE];
pub type Randomness = Scalar;

// Additional info for the key derivation. Contains the object id for the key server and the share index.
pub type Info = (ObjectID, u8);

/// Generate a key pair consisting of a master key and a public key.
pub fn generate_key_pair<R: AllowedRng>(rng: &mut R) -> (MasterKey, PublicKey) {
    let sk = Scalar::rand(rng);
    (sk, public_key_from_master_key(&sk))
}

/// Derive a public key from a master key.
pub fn public_key_from_master_key(master_key: &MasterKey) -> PublicKey {
    G2Element::generator() * master_key
}

/// Extract a user secret key from a master key and an id.
pub fn extract(master_key: &MasterKey, id: &[u8]) -> UserSecretKey {
    G1Element::hash_to_group_element(id) * master_key
}

/// Verify that a user secret key is valid for a given public key and id.
pub fn verify_user_secret_key(
    user_secret_key: &UserSecretKey,
    id: &[u8],
    public_key: &PublicKey,
) -> FastCryptoResult<()> {
    if user_secret_key.pairing(&G2Element::generator())
        == G1Element::hash_to_group_element(id).pairing(public_key)
    {
        Ok(())
    } else {
        Err(InvalidInput)
    }
}

/// Encrypt a set of messages for a given identity but different public keys.
/// The infos are used to derive the symmetric keys for the encryption.
pub fn encrypt_batched_deterministic(
    randomness: &Randomness,
    plaintexts: &[Plaintext],
    public_keys: &[PublicKey],
    id: &[u8],
    infos: &[Info],
) -> FastCryptoResult<(Nonce, Vec<Ciphertext>)> {
    let batch_size = plaintexts.len();
    if batch_size != public_keys.len() || batch_size != infos.len() {
        return Err(InvalidInput);
    }

    let gid = G1Element::hash_to_group_element(id);
    let gid_r = gid * randomness;
    let nonce = G2Element::generator() * randomness;
    Ok((
        nonce,
        (0..batch_size)
            .map(|i| {
                xor(
                    &kdf(&gid_r.pairing(&public_keys[i]), &nonce, &gid, &infos[i]),
                    &plaintexts[i],
                )
            })
            .collect(),
    ))
}

/// Decrypt a message with the given user secret key and the encapsulation.
/// The info is used to derive the symmetric key for the decryption and should be the same as the one used for the encryption.
pub fn decrypt(
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    secret_key: &UserSecretKey,
    id: &[u8],
    info: &Info,
) -> Plaintext {
    let gid = G1Element::hash_to_group_element(id);
    xor(
        ciphertext,
        &kdf(&secret_key.pairing(nonce), nonce, &gid, info),
    )
}

/// Verify that the given randomness was used to crate the nonce.
fn verify_nonce(randomness: &Randomness, nonce: &Nonce) -> FastCryptoResult<()> {
    if G2Element::generator() * randomness != *nonce {
        return Err(GeneralError("Invalid randomness".to_string()));
    }
    Ok(())
}

/// Decrypt a message using given randomness.
/// The info is used to derive the symmetric key for the decryption and should be the same as the one used for the encryption.
pub fn decrypt_deterministic(
    randomness: &Randomness,
    ciphertext: &Ciphertext,
    public_key: &PublicKey,
    id: &[u8],
    info: &Info,
) -> FastCryptoResult<Plaintext> {
    let gid = G1Element::hash_to_group_element(id);
    let gid_r = gid * randomness;
    let nonce = G2Element::generator() * randomness;
    Ok(xor(
        ciphertext,
        &kdf(&gid_r.pairing(public_key), &nonce, &gid, info),
    ))
}

/// Derive a random key from public inputs.
fn kdf(
    input: &GTElement,
    nonce: &G2Element,
    gid: &G1Element,
    (object_id, index): &Info,
) -> [u8; KEY_SIZE] {
    let mut bytes = input.to_byte_array().to_vec(); // 576 bytes
    bytes.extend_from_slice(&nonce.to_byte_array()); // 96 bytes
    bytes.extend_from_slice(&gid.to_byte_array()); // 48 bytes

    let mut info = object_id.to_vec();
    info.extend_from_slice(&[*index]);

    hkdf_sha3_256(
        &HkdfIkm::from_bytes(&bytes).expect("not fixed length"),
        &[], // no salt
        &info,
        KEY_SIZE,
    )
    .expect("kdf should not fail")
    .try_into()
    .expect("same length")
}

/// Encrypt the Randomness using a key.
pub fn encrypt_randomness(randomness: &Randomness, key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    xor(key, &randomness.to_byte_array())
}

/// Decrypt the Randomness using a key and verify that the randomness was used to create the given nonce.
pub fn decrypt_and_verify_nonce(
    encrypted_randomness: &[u8; KEY_SIZE],
    derived_key: &[u8; KEY_SIZE],
    nonce: &Nonce,
) -> FastCryptoResult<Randomness> {
    let randomness = Scalar::from_byte_array(&xor(derived_key, encrypted_randomness))?;
    verify_nonce(&randomness, nonce).map(|()| randomness)
}

pub type ProofOfPossession = G1Element;

/// Create a proof-of-possession of the master key, binding it to a specific message.
/// It is created as a BLS signature over the public key and the message.
pub fn create_proof_of_possession(master_key: &MasterKey, message: &[u8]) -> ProofOfPossession {
    let public_key = public_key_from_master_key(master_key);
    let mut full_msg = DST_POP.to_vec();
    full_msg.extend(bcs::to_bytes(&public_key).expect("valid pk"));
    full_msg.extend(message);
    G1Element::hash_to_group_element(&full_msg) * master_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_alignment_with_ts() {
        use fastcrypto::groups::GroupElement;

        let r = fastcrypto::groups::bls12381::Scalar::from(12345u128);
        let x = GTElement::generator() * r;
        let nonce = G2Element::generator() * r;
        let gid = G1Element::hash_to_group_element(&[0]);
        let object_id = ObjectID::new([0; 32]);

        let derived_key = kdf(&x, &nonce, &gid, &(object_id, 42));
        let expected =
            hex::decode("1963b93f076d0dc97cbb38c3864b2d6baeb87c7eb99139100fd775b0b09f668b")
                .unwrap();
        assert_eq!(expected, derived_key);
    }
}
