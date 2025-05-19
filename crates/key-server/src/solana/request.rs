use crate::types::{ElGamalPublicKey, ElgamalVerificationKey};
use crate::solana::types::RequestFormat;
use crate::errors::InternalError;
use bcs;
use bincode;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::VerifyingKey;
use hex;
use solana_sdk::transaction::Transaction;
use tracing::debug;

/// Create message bytes for request signing
pub fn message_for_request(
    transaction_bytes: &[u8],
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
) -> Vec<u8> {
    // For Solana, we don't need to slice like in Sui
    let req = RequestFormat {
        ptb: transaction_bytes.to_vec(),
        enc_key: bcs::to_bytes(enc_key).expect("should serialize"),
        enc_verification_key: bcs::to_bytes(enc_verification_key).expect("should serialize"),
    };

    println!(
        "Request bytes length: {}",
        bcs::to_bytes(&req).expect("should serialize").len()
    );

    bcs::to_bytes(&req).expect("should serialize")
}

/// Verify request signature
pub fn verify_request_signature(
    transaction: &Transaction,
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
    request_signature: &Ed25519Signature,
    session_vk: &Ed25519PublicKey,
    req_id: Option<&str>,
) -> Result<(), InternalError> {
    // Serialize the transaction to bytes
    let transaction_bytes = bincode::serialize(transaction)
        .map_err(|_| InternalError::InvalidPTB("Failed to serialize transaction".to_string()))?;

    println!("transaction_bytes length: {}", transaction_bytes.len());
    println!(
        "transaction_bytes (hex): {}",
        hex::encode(&transaction_bytes)
    );

    // Create the signed request data - same format as in Sui version
    let request_bytes = message_for_request(&transaction_bytes, enc_key, enc_verification_key);
    println!("Request bytes length: {}", request_bytes.len());
    println!("Request bytes (hex): {}", hex::encode(&request_bytes));

    // Log the signature and verification key
    println!(
        "Signature (hex): {}",
        hex::encode(request_signature.as_ref())
    );
    println!(
        "Verification key (hex): {}",
        hex::encode(session_vk.as_ref())
    );

    // Verify the Ed25519 signature using session verification key
    if session_vk
        .verify(&request_bytes, request_signature)
        .is_err()
    {
        debug!(
            "Request signature verification failed (req_id: {:?})",
            req_id
        );
        return Err(InternalError::InvalidSignature);
    }

    println!(
        "Request signature verification passed (req_id: {:?})",
        req_id
    );

    Ok(())
} 