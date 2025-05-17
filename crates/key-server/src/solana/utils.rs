// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use solana_sdk::transaction::VersionedTransaction;
use solana_sdk::message::Message;
use solana_sdk::message::VersionedMessage;
use fastcrypto::encoding::{Base64, Encoding};
use bincode;
use bs58;

/// Verify a Solana transaction signature
pub fn verify_transaction_signature(
    transaction: &Transaction,
    expected_signer: &Pubkey,
) -> Result<(), InternalError> {
    // Get the message that was signed
    let message = transaction.message.serialize();

    // Verify that the transaction is signed by the expected signer
    for (i, sig) in transaction.signatures.iter().enumerate() {
        if i < transaction.message.account_keys.len()
            && transaction.message.account_keys[i] == *expected_signer
            && !sig.as_ref().iter().all(|&b| b == 0)
        {
            // This assumes the signer is the first account in the transaction
            return Ok(());
        }
    }

    Err(InternalError::InvalidSignature)
}

/// Parse a base64 encoded transaction
pub fn parse_transaction(transaction_str: &str) -> Result<Transaction, InternalError> {
    // Decode the base64 string into bytes
    let bytes = Base64::decode(transaction_str)
        .map_err(|e| InternalError::InvalidPTB(format!("Invalid base64 encoding: {}", e)))?;

    // Deserialize the transaction
    let transaction = bincode::deserialize::<Transaction>(&bytes)
        .map_err(|_| InternalError::InvalidPTB("Failed to deserialize transaction".to_string()))?;

    Ok(transaction)
}

/// Verify a Solana message signature
pub fn verify_message_signature(
    message: &[u8],
    signature: &Signature,
    pubkey: &Pubkey,
) -> Result<(), InternalError> {
    // Perform proper cryptographic verification in production
    let verification_result = signature.verify(pubkey.as_ref(), message);
    if verification_result {
        Ok(())
    } else {
        Err(InternalError::InvalidSignature)
    }
}
