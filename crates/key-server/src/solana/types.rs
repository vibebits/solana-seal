use serde::{Deserialize, Serialize, Deserializer};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::encoding::{Base64, Encoding};
use std::str::FromStr;
use crate::types::{ElGamalPublicKey, ElgamalEncryption, ElgamalVerificationKey};

/// The "session" certificate for Solana, signed by the user
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub user: Pubkey,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    #[serde(deserialize_with = "deserialize_signature")]
    pub signature: Signature,
}

/// Custom deserializer for Pubkey that accepts base58 string
fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}

/// Custom deserializer for Signature that accepts base64 string
fn deserialize_signature<'de, D>(deserializer: D) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let bytes = Base64::decode(&s).map_err(serde::de::Error::custom)?;
    if bytes.len() != 64 {
        return Err(serde::de::Error::custom("Invalid signature length"));
    }
    Ok(Signature::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)?)
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyRequest {
    // Solana transaction that must be signed to prevent others from sending requests
    pub ptb: String, // Base58 encoded transaction
    pub enc_key: ElGamalPublicKey,
    pub enc_verification_key: ElgamalVerificationKey,
    pub request_signature: Ed25519Signature, // Changed from Signature to Ed25519Signature
    pub certificate: Certificate,
}

// Key ID for Solana is a vector of bytes
type KeyId = Vec<u8>;

#[derive(Serialize, Deserialize)]
pub struct DecryptionKey {
    pub id: KeyId,
    pub encrypted_key: ElgamalEncryption,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyResponse {
    pub decryption_keys: Vec<DecryptionKey>,
}

#[derive(Serialize, Deserialize)]
pub struct RequestFormat {
    pub ptb: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub enc_verification_key: Vec<u8>,
} 