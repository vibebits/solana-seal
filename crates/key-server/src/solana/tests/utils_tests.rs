// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::solana::utils::*;
use solana_sdk::system_program;
use solana_sdk::instruction::Instruction;
use solana_sdk::signature::Keypair;
use solana_sdk::signature::Signer;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::message::Message;
use solana_sdk::transaction::{Transaction, VersionedTransaction};
use solana_sdk::system_instruction;
use fastcrypto::encoding::{Base64, Encoding};

#[test]
fn test_verify_transaction_signature() {
    // Create a keypair for signing
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();

    // Create a simple transfer instruction
    let instruction = system_instruction::transfer(
        &pubkey,
        &Pubkey::new_unique(),
        100,
    );

    // Create and sign a transaction
    let recent_blockhash = solana_sdk::hash::Hash::new_unique();
    let message = Message::new(&[instruction.clone()], Some(&pubkey));
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&pubkey),
        &[&keypair],
        recent_blockhash,
    );

    // Test valid signature
    assert!(verify_transaction_signature(&transaction, &pubkey).is_ok());

    // Test invalid signer
    let wrong_pubkey = Pubkey::new_unique();
    assert!(verify_transaction_signature(&transaction, &wrong_pubkey).is_err());
}

#[test]
fn test_parse_transaction() {
    // Create a keypair and transaction
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    let instruction = system_instruction::transfer(
        &pubkey,
        &Pubkey::new_unique(),
        100,
    );
    let recent_blockhash = solana_sdk::hash::Hash::new_unique();
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&pubkey),
        &[&keypair],
        recent_blockhash,
    );

    // Convert to VersionedTransaction
    let versioned_tx = VersionedTransaction::from(transaction);

    // Serialize and encode the transaction
    let serialized = bincode::serialize(&versioned_tx).unwrap();
    let encoded = Base64::encode(&serialized);

    // Test parsing
    let parsed = parse_transaction(&encoded).unwrap();
    assert_eq!(parsed.message.account_keys[0], pubkey);

    // Test invalid base64
    assert!(parse_transaction("invalid").is_err());
}

#[test]
fn test_verify_message_signature() {
    // Create a keypair
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();

    // Create a message and sign it
    let message = b"Hello, Solana!";
    let signature = keypair.sign_message(message);

    // Test valid signature
    assert!(verify_message_signature(message, &signature, &pubkey).is_ok());

    // Test invalid signature
    let wrong_pubkey = Pubkey::new_unique();
    assert!(verify_message_signature(message, &signature, &wrong_pubkey).is_err());

    // Test invalid message
    let wrong_message = b"Wrong message";
    assert!(verify_message_signature(wrong_message, &signature, &pubkey).is_err());
} 