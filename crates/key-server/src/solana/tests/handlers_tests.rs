// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::metrics::Metrics;
use crate::MyState;
use crate::Server;
use crate::solana::handlers::handle_fetch_key_solana;
use crate::solana::types::{SolanaCertificate, FetchKeySolanaRequest, FetchKeySolanaResponse};
use crate::types::{ElGamalPublicKey, ElgamalVerificationKey, Network, IbeMasterKey};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use crypto::elgamal;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature, Ed25519PrivateKey, Ed25519KeyPair};
use fastcrypto::traits::{KeyPair, ToFromBytes, SigningKey, VerifyingKey, Signer};
use prometheus::Registry;
use rand::thread_rng;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer as SolanaSigner};
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch::channel;
use bs58;
use chrono;
use hex;

// Define constants for tests that match the ones in handlers.rs
static SOLANA_PROGRAM_ID: Pubkey = Pubkey::new_from_array([1; 32]);
const SOLANA_APPROVE_INSTRUCTION_DATA_PREFIX: &[u8] = &[0]; // Instruction index for seal_approve

// Helper function to create a test transaction
fn create_test_transaction(keypair: &Keypair) -> (Transaction, String) {
    let pubkey = keypair.pubkey();
    
    // Create a simple transfer instruction
    let system_instruction = system_instruction::transfer(
        &pubkey,
        &Pubkey::new_unique(),
        100,
    );
    
    // For testing, create a random program ID instead of trying to parse the real one
    // This avoids the parsing error and is sufficient for tests since the mock policy check
    // will be used in test mode
    let seal_program_id = SOLANA_PROGRAM_ID;
    println!("Using test program ID: {}", seal_program_id);
    
    // Mark one of the instructions as a Seal program instruction to satisfy the policy check
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(pubkey, true),
        solana_sdk::instruction::AccountMeta::new(Pubkey::new_unique(), false)
    ];
    
    // Create instruction data with the approval prefix
    let mut instruction_data = Vec::new();
    instruction_data.extend_from_slice(SOLANA_APPROVE_INSTRUCTION_DATA_PREFIX);
    instruction_data.extend_from_slice(b"test_data");
    
    let seal_instruction = solana_sdk::instruction::Instruction {
        program_id: seal_program_id,
        accounts,
        data: instruction_data,
    };
    
    // Create and sign a transaction with both instructions
    let recent_blockhash = Hash::new_unique();
    let transaction = Transaction::new_signed_with_payer(
        &[system_instruction.clone(), seal_instruction],
        Some(&pubkey),
        &[keypair],
        recent_blockhash,
    );
    
    // Serialize and encode the transaction
    let serialized = bincode::serialize(&transaction).unwrap();
    let encoded = bs58::encode(serialized).into_string();
    
    (transaction, encoded)
}

// Helper function to create a test master key
fn create_test_master_key() -> IbeMasterKey {
    // Create a deterministic scalar for testing 
    fastcrypto::groups::bls12381::Scalar::from(12345u128)
}

// Helper function to create ElGamal keys for testing
fn create_test_elgamal_keys(master_key: &IbeMasterKey) -> (ElGamalPublicKey, ElgamalVerificationKey) {
    let rng = &mut thread_rng();
    let (_, pk, vk) = elgamal::genkey(rng);
    (pk, vk)
}

// Helper function to create a certificate with Solana Signature
fn create_certificate(
    user: Pubkey,
    session_vk: Ed25519PublicKey,
    creation_time: u64,
    ttl_min: u16,
    keypair: &Keypair,
) -> SolanaCertificate {
    // Format the message exactly as expected in handlers.rs check_certificate_signature_solana function
    let message = format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        SOLANA_PROGRAM_ID.to_string(),
        ttl_min,
        chrono::DateTime::<chrono::Utc>::from_timestamp((creation_time / 1000) as i64, 0)
            .expect("valid timestamp"),
        session_vk,
    );

    // log the message
    println!("Message to verify: {}", message);
    
    // Sign using Solana keypair
    let signature = keypair.sign_message(message.as_bytes());
    
    // Create certificate with the signature
    SolanaCertificate {
        user,
        session_vk,
        creation_time,
        ttl_min,
        signature,
    }
}

// Re-use the signed_request_solana function from handlers.rs
fn signed_request_solana(
    transaction_bytes: &[u8],
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
) -> Vec<u8> {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct RequestFormatSolana {
        ptb: Vec<u8>,
        enc_key: Vec<u8>,
        enc_verification_key: Vec<u8>,
    }

    let req = RequestFormatSolana {
        ptb: transaction_bytes.to_vec(),
        enc_key: bcs::to_bytes(enc_key).expect("should serialize"),
        enc_verification_key: bcs::to_bytes(enc_verification_key).expect("should serialize"),
    };
    
    bcs::to_bytes(&req).expect("should serialize")
}

#[tokio::test]
async fn test_handle_fetch_key_solana() {
    // Create test environment
    let master_key = create_test_master_key();
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::new(&registry));
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    // Create test channels
    let (checkpoint_sender, checkpoint_receiver) = channel(timestamp);
    let (gas_price_sender, gas_price_receiver) = channel(100u64);
    
    // Create test server
    let server = Arc::new(
        Server::new(
            master_key.clone(),
            Network::Testnet,
            sui_sdk::types::base_types::ObjectID::random(),
        )
        .await,
    );
    
    // Create app state
    let app_state = MyState {
        metrics: metrics.clone(),
        server: server.clone(),
        latest_checkpoint_timestamp_receiver: checkpoint_receiver,
        reference_gas_price: gas_price_receiver,
    };
    
    // Generate test keys
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    
    // Create a session keypair (Ed25519)
    let mut rng = thread_rng();
    let session_kp = Ed25519KeyPair::generate(&mut rng);
    let session_vk = session_kp.public().clone();

    println!("Public key: {}", pubkey);
    println!("Session verification key: {}", session_vk);

    // Create a mock certificate
    let certificate = create_certificate(
        pubkey,
        session_vk.clone(),
        timestamp - 1000, // 1 second ago
        15,             // 15 minutes TTL
        &keypair,
    );
    
    // Create the transaction and get its encoded form
    let (tx, encoded_tx) = create_test_transaction(&keypair);
    
    // Create ElGamal keys for encryption
    let (enc_key, enc_vk) = create_test_elgamal_keys(&server.master_key);
    
    // Create the request signature using Ed25519
    let transaction_bytes = bs58::decode(&encoded_tx).into_vec().expect("Should decode base58");
    
    // Create request data using the same method as in handlers.rs
    let request_data = signed_request_solana(&transaction_bytes, &enc_key, &enc_vk);
    
    println!("Request data length: {}", request_data.len());
    
    let request_signature: Ed25519Signature = session_kp.sign(&request_data);
    println!("Request signature: {}", hex::encode(request_signature.as_ref()));
    
    // Verify locally that the signature is valid
    let verify_result = session_vk.verify(&request_data, &request_signature);
    println!("Local verification result: {:?}", verify_result);
    
    // Create request
    let request = FetchKeySolanaRequest {
        ptb: encoded_tx,
        enc_key,
        enc_verification_key: enc_vk,
        request_signature,
        certificate: certificate.clone(),
    };
    
    // Create headers
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", "test-request-id".parse().unwrap());
    
    // Call the handler
    let result = handle_fetch_key_solana(
        State(app_state),
        headers,
        Json(request),
    )
    .await;
    
    // Verify the result
    assert!(result.is_ok(), "Handler should succeed: {:?}", result.err());
    
    let response = result.unwrap();
    let decryption_keys = response.0.decryption_keys;
    
    // We should have at least one key
    assert!(!decryption_keys.is_empty(), "Response should contain at least one key");
    
    // Each key should have an ID and encrypted key data
    for key in decryption_keys {
        assert!(!key.id.is_empty(), "Key ID should not be empty");
        // We can't actually decrypt the key here, but we can check if it has data
        assert!(
            !bincode::serialize(&key.encrypted_key).unwrap().is_empty(),
            "Encrypted key should not be empty"
        );
    }
}

#[tokio::test]
async fn test_handle_fetch_key_solana_invalid_signature() {
    // Create test environment
    let master_key = create_test_master_key();
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::new(&registry));
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    // Create test channels
    let (checkpoint_sender, checkpoint_receiver) = channel(timestamp);
    let (gas_price_sender, gas_price_receiver) = channel(100u64);
    
    // Create test server
    let server = Arc::new(
        Server::new(
            master_key.clone(),
            Network::Testnet,
            sui_sdk::types::base_types::ObjectID::random(),
        )
        .await,
    );
    
    // Create app state
    let app_state = MyState {
        metrics: metrics.clone(),
        server: server.clone(),
        latest_checkpoint_timestamp_receiver: checkpoint_receiver,
        reference_gas_price: gas_price_receiver,
    };
    
    // Generate test keys
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    
    // Create correct and wrong Ed25519KeyPair
    let mut rng = thread_rng();
    let session_kp = Ed25519KeyPair::generate(&mut rng);
    let wrong_session_kp = Ed25519KeyPair::generate(&mut rng);
    let session_vk = session_kp.public().clone();

    // Create a mock certificate
    let certificate = create_certificate(
        pubkey,
        session_vk.clone(),
        timestamp - 1000, // 1 second ago
        15,             // 15 minutes TTL
        &keypair,
    );
    
    // Create the transaction and get its encoded form
    let (tx, encoded_tx) = create_test_transaction(&keypair);
    
    // Create ElGamal keys for encryption
    let (enc_key, enc_vk) = create_test_elgamal_keys(&server.master_key);
    
    // Create request data using the same method as in handlers.rs
    let transaction_bytes = bs58::decode(&encoded_tx).into_vec().expect("Should decode base58");
    let request_data = signed_request_solana(&transaction_bytes, &enc_key, &enc_vk);
    
    // Create an invalid request signature (using wrong_session_kp)
    let request_signature: Ed25519Signature = wrong_session_kp.sign(&request_data);
    
    // Create request
    let request = FetchKeySolanaRequest {
        ptb: encoded_tx,
        enc_key,
        enc_verification_key: enc_vk,
        request_signature,
        certificate: certificate.clone(),
    };
    
    // Create headers
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", "test-request-id".parse().unwrap());
    
    // Call the handler
    let result = handle_fetch_key_solana(
        State(app_state),
        headers,
        Json(request),
    )
    .await;
    
    // Should fail due to invalid signature
    assert!(result.is_err(), "Handler should fail with invalid signature");
    match result {
        Err(InternalError::InvalidSignature) => {} // Expected error
        Err(e) => panic!("Unexpected error: {:?}", e),
        Ok(_) => panic!("Expected an error, but got success"),
    }
}

#[tokio::test]
async fn test_handle_fetch_key_solana_expired_certificate() {
    // Create test environment
    let master_key = create_test_master_key();
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::new(&registry));
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    // Create test channels
    let (checkpoint_sender, checkpoint_receiver) = channel(timestamp);
    let (gas_price_sender, gas_price_receiver) = channel(100u64);
    
    // Create test server
    let server = Arc::new(
        Server::new(
            master_key.clone(),
            Network::Testnet,
            sui_sdk::types::base_types::ObjectID::random(),
        )
        .await,
    );
    
    // Create app state
    let app_state = MyState {
        metrics: metrics.clone(),
        server: server.clone(),
        latest_checkpoint_timestamp_receiver: checkpoint_receiver,
        reference_gas_price: gas_price_receiver,
    };
    
    // Generate test keys
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    
    // Create a session keypair
    let mut rng = thread_rng();
    let session_kp = Ed25519KeyPair::generate(&mut rng);
    let session_vk = session_kp.public().clone();

    // Create an expired certificate
    let expired_time = timestamp - 60_000 * 60; // 60 minutes ago
    let certificate = create_certificate(
        pubkey,
        session_vk.clone(),
        expired_time,
        15, // 15 minutes TTL
        &keypair,
    );
    
    // Create the transaction and get its encoded form
    let (tx, encoded_tx) = create_test_transaction(&keypair);
    
    // Create ElGamal keys for encryption
    let (enc_key, enc_vk) = create_test_elgamal_keys(&server.master_key);
    
    // Create request data using the same method as in handlers.rs
    let transaction_bytes = bs58::decode(&encoded_tx).into_vec().expect("Should decode base58");
    let request_data = signed_request_solana(&transaction_bytes, &enc_key, &enc_vk);
    
    // Create the request signature
    let request_signature: Ed25519Signature = session_kp.sign(&request_data);
    
    // Create request
    let request = FetchKeySolanaRequest {
        ptb: encoded_tx,
        enc_key,
        enc_verification_key: enc_vk,
        request_signature,
        certificate,
    };
    
    // Create headers
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", "test-request-id".parse().unwrap());
    
    // Call the handler
    let result = handle_fetch_key_solana(
        State(app_state),
        headers,
        Json(request),
    )
    .await;
    
    // Should fail due to expired certificate
    assert!(result.is_err(), "Handler should fail with expired certificate");
    match result {
        Err(InternalError::InvalidCertificate) => {} // Expected error
        Err(e) => panic!("Unexpected error: {:?}", e),
        Ok(_) => panic!("Expected an error, but got success"),
    }
} 