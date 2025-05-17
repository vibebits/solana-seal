// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::current_epoch_time;
use crate::errors::InternalError;
use crate::metrics::Metrics;
use crate::solana::types::{
    DecryptionKeySolana, ElGamalPublicKey, ElgamalVerificationKey, FetchKeySolanaRequest,
    FetchKeySolanaResponse, SolanaCertificate,
};
use crate::solana::utils::{parse_transaction, verify_message_signature};
use crate::MyState;
use crate::ALLOWED_STALENESS;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use bincode;
use chrono::{DateTime, Utc};
use crypto::create_full_id;
use crypto::elgamal::encrypt;
use crypto::ibe::extract;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::VerifyingKey;
use hex;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
use std::str::FromStr;
use std::time::Instant;
use tap::tap::TapFallible;
use tracing::{debug, info, warn};
use ureq;
use serde_json::{json, Value};

// Define constants for Solana
const SEAL_APPROVE_DISCRIMINATOR: &[u8; 8] = &[114, 84, 92, 48, 48, 9, 84, 182];
const SOLANA_RPC_ENDPOINT: &str = "http://localhost:8899"; // Use public endpoint
const SESSION_KEY_TTL_MAX: u16 = 30;

#[derive(Serialize, Deserialize)]
struct RequestFormatSolana {
    ptb: Vec<u8>,
    enc_key: Vec<u8>,
    enc_verification_key: Vec<u8>,
}

/// Create request bytes in the same format as the original signed_request function
fn signed_request_solana(
    transaction_bytes: &[u8],
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
) -> Vec<u8> {
    // For Solana, we don't need to slice like in Sui
    let req = RequestFormatSolana {
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

/// Helper function to check if an instruction is a Seal program instruction
fn is_seal_program_instruction(
    instruction: &solana_sdk::instruction::CompiledInstruction,
    approved_program_id: &Pubkey,
    account_keys: &[Pubkey],
) -> bool {
    // Get the program ID actually called by this instruction
    if let Some(invoked_program_id) = account_keys.get(instruction.program_id_index as usize) {
        if invoked_program_id != approved_program_id {
            return false; // Not an instruction for our target program
        }
    } else {
        // Should not happen with a valid transaction and compiled instruction
        warn!("program_id_index out of bounds in instruction");
        return false;
    }

    // Expected discriminator for `seal_approve`
    if instruction.data.len() >= 8 && &instruction.data[0..8] == SEAL_APPROVE_DISCRIMINATOR {
        return true;
    }
    // Potentially other discriminators for other functions can be checked here.
    false
}

/// Extract key IDs from transaction instructions
fn extract_key_ids_from_transaction(
    transaction: &Transaction,
    program_id: &Pubkey,
) -> Result<Vec<Vec<u8>>, InternalError> {
    // Look for instructions that call our Seal program
    let mut key_ids = Vec::new();
    let account_keys = &transaction.message.account_keys;

    for ix in &transaction.message.instructions {
        if is_seal_program_instruction(ix, program_id, account_keys) {
            // This instruction is confirmed to be `seal_approve` for our program.
            // Instruction data format by Anchor for `id: Vec<u8>`:
            // - 8 bytes: discriminator
            // - 4 bytes: length of the vector (u32 LE)
            // - N bytes: content of the vector (this is our encryptionId as bytes)

            if ix.data.len() < 8 + 4 {
                // Must have at least discriminator + length
                warn!(
                    "seal_approve instruction data too short to contain id length: {}. Expected at least 12.",
                    ix.data.len()
                );
                continue;
            }

            // Skip discriminator (8 bytes)
            let data_after_discriminator = &ix.data[8..];

            // Read length of the id vector (4 bytes LE)
            let mut id_len_bytes = [0u8; 4];
            id_len_bytes.copy_from_slice(&data_after_discriminator[0..4]);
            let id_len = u32::from_le_bytes(id_len_bytes) as usize;

            if data_after_discriminator.len() < 4 + id_len {
                warn!(
                    "seal_approve instruction data too short for declared id length. Declared: {}, Available: {}.",
                    id_len,
                    data_after_discriminator.len() - 4
                );
                continue;
            }

            // Extract the id_bytes (this is the encryptionId)
            let id_bytes = &data_after_discriminator[4..4 + id_len];
            println!(
                "Extracted encryptionId (instruction data): {:?}",
                hex::encode(id_bytes)
            );

            // Create the full ID using these extracted id_bytes.
            // The `program_id` for `create_full_id` should be the actual program ID of our seal program.
            let full_id = create_full_id(&program_id.to_bytes(), id_bytes);
            println!(
                "Created full ID from extracted encryptionId: {:?}",
                hex::encode(&full_id)
            );

            key_ids.push(full_id);
        }
    }

    if key_ids.is_empty() {
        return Err(InternalError::InvalidPTB(
            "No key IDs found in transaction".to_string(),
        ));
    }

    Ok(key_ids)
}

/// Check certificate validity
fn check_certificate_solana(
    certificate: &SolanaCertificate,
    req_id: Option<&str>,
) -> Result<(), InternalError> {
    // Check certificate TTL and creation time
    let current_time = current_epoch_time();

    if certificate.ttl_min > SESSION_KEY_TTL_MAX
        || certificate.creation_time > current_time
        || current_time < 60_000 * (certificate.ttl_min as u64) // check for overflow
        || current_time - 60_000 * (certificate.ttl_min as u64) > certificate.creation_time
    {
        debug!(
            "Certificate has invalid expiration time (req_id: {:?})",
            req_id
        );
        return Err(InternalError::InvalidCertificate);
    }

    Ok(())
}

/// Verify certificate signature
fn check_certificate_signature_solana(
    certificate: &SolanaCertificate,
    program_id_str: &str,
    req_id: Option<&str>,
) -> Result<(), InternalError> {
    // Create message to verify
    let message = format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        program_id_str,
        certificate.ttl_min,
        DateTime::<Utc>::from_timestamp((certificate.creation_time / 1000) as i64, 0)
            .expect("valid timestamp"),
        certificate.session_vk,
    );

    // log the message
    debug!("Message to verify: {}", message);
    println!("Message to verify: {}", message);

    // Verify Solana signature
    println!("### Verifying certificate signature ###");
    // println!("Message bytes: {:?}", message.as_bytes());
    // println!("Signature bytes: {:?}", certificate.signature);
    println!("certificate user pubkey: {:?}", certificate.user);

    // verify certificate signature
    verify_message_signature(
        message.as_bytes(),
        &certificate.signature,
        &certificate.user,
    )
    .tap_err(|e| {
        println!("### Certificate Signature verification failed: {:?}", e);
        debug!(
            "Certificate signature invalid: {:?} (req_id: {:?})",
            e, req_id
        )
    })
}

/// Verify request signature
fn check_request_signature_solana(
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
    let request_bytes = signed_request_solana(&transaction_bytes, enc_key, enc_verification_key);
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

/// Check policy via transaction simulation
async fn check_policy_solana(
    transaction: &Transaction,
    program_id: &Pubkey,
    certificate_user_pubkey: &Pubkey,
    req_id: Option<&str>,
) -> Result<Vec<Vec<u8>>, InternalError> {
    debug!(
        "Checking policy for Solana transaction (req_id: {:?})",
        req_id
    );
    debug!(
        "program_id: {:?}, certificate_user_pubkey: {:?}",
        program_id, certificate_user_pubkey
    );
    let account_keys = &transaction.message.account_keys;

    // Check if the user account is in the transaction
    let account_in_tx = transaction
        .message
        .account_keys
        .iter()
        .any(|key| key == certificate_user_pubkey);

    println!("account_in_tx: {}", account_in_tx);

    // TODO: for security, it is good to have pubkey of the user who signed the certificate
    // if !account_in_tx {
    //     debug!(
    //         "User account not found in transaction (req_id: {:?})",
    //         req_id
    //     );
    //     return Err(InternalError::NoAccess);
    // }

    // Check if any instruction in the transaction calls the program as approved in the certificate
    // this is important for security
    let seal_instruction = transaction
        .message
        .instructions
        .iter()
        .find(|ix| is_seal_program_instruction(ix, program_id, account_keys));

    if seal_instruction.is_none() {
        debug!("No Seal program instruction found (req_id: {:?})", req_id);
        return Err(InternalError::InvalidPTB(
            "No Seal program instruction found".to_string(),
        ));
    }

    // continue with transaction simulation as there is at least one relevant instruction

    println!("### starting transaction simulation ###");

    // Simulate transaction on Solana to check policy
    let serialized_tx = bincode::serialize(transaction).unwrap();
    let base64_tx = Base64::encode(&serialized_tx);

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": [
            base64_tx,
            {
                "commitment": "confirmed",
                "encoding": "base64",
                "replaceRecentBlockhash": true
            }
        ]
    });

    println!("### simulation request_body: {:?}", request_body);

    let response = ureq::post(SOLANA_RPC_ENDPOINT)
        .set("Content-Type", "application/json")
        .send_json(request_body)
        .map_err(|e| {
            println!("### simulate error: {:?}", e);
            warn!("Solana RPC request failed: {:?} (req_id: {:?})", e, req_id);
            InternalError::Failure
        })?;

    let response_text = response.into_string().map_err(|e| {
        warn!(
            "Failed to parse Solana RPC response: {:?} (req_id: {:?})",
            e, req_id
        );
        InternalError::Failure
    })?;

    let response_json: Value = serde_json::from_str(&response_text).map_err(|e| {
        warn!(
            "Failed to parse Solana RPC response: {:?} (req_id: {:?})",
            e, req_id
        );
        InternalError::Failure
    })?;

    // println!("### simulation response_json: {:?}", response_json);

    // Check if there are any errors in the simulation result
    let result_value = response_json
        .get("result")
        .and_then(|r| r.get("value")) // Get the nested "value" object
        .ok_or_else(|| {
            warn!(
                "Missing 'result.value' in Solana simulation result (req_id: {:?})",
                req_id
            );
            InternalError::Failure
        })?;

    if let Some(err) = result_value.get("err") { // Check err in the 'value' object
        if !err.is_null() {
            println!("### Solana simulation returned error: {:?} (req_id: {:?})", err, req_id);
            if let Some(logs) = result_value.get("logs") { // Get logs from 'value' for error context
                println!("### Program logs on error: {:?}", logs);
            }
            debug!(
                "Solana simulation returned error: {:?} (req_id: {:?})",
                err, req_id
            );
            return Err(InternalError::NoAccess);
        }
    }

    // println!("### simulation result value: {:?}", result_value); // Prints the "value" object

    // Extract and process "Program return:" logs for seal_approve outcomes
    let program_id_for_log = program_id.to_string();
    let mut seal_approve_outcomes: Vec<bool> = Vec::new();

    let logs = result_value // Get logs from the 'value' object
        .get("logs")
        .and_then(|l| l.as_array())
        .ok_or_else(|| {
            warn!(
                "Missing or invalid logs array in Solana simulation result (req_id: {:?})",
                req_id
            );
            InternalError::Failure
        })?;

    println!("### simulation logs: {:?} for program: {}", logs.len(), program_id_for_log);
    for log_value in logs {
        if let Some(log_str) = log_value.as_str() {
            // Anchor typically logs returns as: "Program log: Program return: <PROGRAM_ID> <BASE64_DATA>"
            // Or sometimes just: "Program return: <PROGRAM_ID> <BASE64_DATA>" if it's not from a top-level CPI log
            
            let relevant_log_part = if log_str.starts_with("Program log: Program return:") {
                log_str.trim_start_matches("Program log: Program return:").trim()
            } else if log_str.starts_with("Program return:") {
                log_str.trim_start_matches("Program return:").trim()
            } else {
                continue; // Not a return log we are interested in
            };

            // Now, relevant_log_part should be "<PROGRAM_ID> <BASE64_DATA>"
            let parts: Vec<&str> = relevant_log_part.split_whitespace().collect();
            println!("### simulation parts from relevant_log_part: {:?}", parts);

            if parts.len() >= 2 {
                // Assume the last part is the base64 data
                let base64_data = parts.last().unwrap(); // .unwrap() is safe due to parts.len() >= 2

                // Check if any of the preceding parts match the program_id_for_log
                let program_id_found = parts[0..parts.len()-1].iter().any(|&p| p == program_id_for_log);

                if program_id_found {
                    match *base64_data { // Dereference base64_data as it's &&str from .last()
                        "AgAAAG9r" => seal_approve_outcomes.push(true), // "ok"
                        "BgAAAG5vdF9vaw==" => seal_approve_outcomes.push(false), // "not_ok"
                        _ => {
                            println!(
                                "Found 'Program return:' log for our program with unexpected data: {} (req_id: {:?})",
                                base64_data,
                                req_id
                            );
                        }
                    }
                } else {
                    // Program ID not found in the expected place, but it was a Program return log.
                    // This might indicate a return from a different program if the initial prefix trim was too broad,
                    // or a malformed log from our program.
                    println!(
                        "Found 'Program return:' log, but program ID {} not found in expected position. Parts: {:?} (req_id: {:?})",
                        program_id_for_log,
                        parts,
                        req_id
                    );
                }
            }
        }
    }

    println!("### simulation seal_approve_outcomes: {:?}", seal_approve_outcomes);

    // Extract key IDs from transaction's instructions
    let key_ids = extract_key_ids_from_transaction(transaction, &program_id)?;

    println!("### seal_approve_outcomes: {:?}, key_ids: {:?}", seal_approve_outcomes.len(), key_ids.len());
    // the lengths should be the same

    // iterate outcomes, if true, add the key_id to valid_key_ids
    let mut valid_key_ids = Vec::new();
    for (i, outcome) in seal_approve_outcomes.iter().enumerate() {
        if *outcome {
            valid_key_ids.push(key_ids[i].clone());
        }
    }
    
    // Example policy: At least one seal_approve call must have occurred and all of them must be "ok" (true).
    if seal_approve_outcomes.is_empty() {
        debug!(
            "No 'Program return:' logs from program {} found with expected 'ok' or 'not_ok' (req_id: {:?})",
            program_id_for_log,
            req_id
        );
        return Err(InternalError::NoAccess); // Or a more specific error
    }

    println!("### valid_key_ids: {:?}", valid_key_ids.len());
    Ok(valid_key_ids)

}

/// Extract program ID from transaction's first instruction
fn extract_program_id_from_transaction(transaction: &Transaction) -> Result<String, InternalError> {
    // return the program id of the first instruction
    let program_id_str = transaction
        .message
        .account_keys
        .get(transaction.message.instructions[0].program_id_index as usize)
        .unwrap()
        .to_string();

    Ok(program_id_str)
}

/// Create response with encrypted keys
fn create_response_solana(
    server: &crate::Server,
    key_ids: &[Vec<u8>],
    enc_key: &ElGamalPublicKey,
) -> FetchKeySolanaResponse {
    let mut decryption_keys = Vec::new();
    let mut rng = thread_rng();

    for id in key_ids {
        // Extract a key based on the ID
        let derived_key = extract(&server.master_key, id);

        // Encrypt the derived key with user's key
        let encrypted_key = encrypt(&mut rng, &derived_key, enc_key);

        println!("extract key for id: {:?}", id);
        // Add to response
        decryption_keys.push(DecryptionKeySolana {
            id: id.clone(),
            encrypted_key,
        });
    }

    FetchKeySolanaResponse { decryption_keys }
}

/// Validate transaction and extract key IDs
async fn check_request_solana(
    transaction: &Transaction,
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
    request_signature: &Ed25519Signature,
    certificate: &SolanaCertificate,
    metrics: Option<&Metrics>,
    req_id: Option<&str>,
    _server: &crate::Server,
) -> Result<Vec<Vec<u8>>, InternalError> {
    let _start = Instant::now();

    // Check certificate validity
    check_certificate_solana(certificate, req_id)?;

    println!(
        "Certificate validity checked successfully (req_id: {:?})",
        req_id
    );

    // Verify request signature (signs over transaction + encryption keys)
    check_request_signature_solana(
        transaction,
        enc_key,
        enc_verification_key,
        request_signature,
        &certificate.session_vk,
        req_id,
    )?;

    println!(
        "Request signature verified successfully (req_id: {:?})",
        req_id
    );

    // Extract program ID from transaction (with 1 or more instructions)
    // we get the program id from the first instruction
    let program_id_str = extract_program_id_from_transaction(transaction)?;
    println!("Program ID: {}", program_id_str);

    // It's already a Solana address, parse it
    let program_id = Pubkey::from_str(&program_id_str)
        .map_err(|_| InternalError::InvalidPTB("Invalid Solana program ID".to_string()))?;

    // Verify signature on the certificate
    // but with the program address from the transaction's first instruction
    check_certificate_signature_solana(certificate, &program_id_str, req_id)?;

    println!(
        "Certificate signature verified successfully (req_id: {:?})",
        req_id
    );

    // Check policy by simulating the transaction
    let valid_key_ids = check_policy_solana(transaction, &program_id, &certificate.user, req_id).await?;
    // TODO: extract key ids from the transaction within check_policy_solana

    println!("Policy checked successfully (req_id: {:?})", req_id);


    println!("Key IDs count: {:?}", valid_key_ids.len());
    println!("Key IDs extracted successfully (req_id: {:?})", req_id);

    // Report metrics if available - using proper field name
    if let Some(m) = metrics {
        m.requests_per_number_of_ids.observe(valid_key_ids.len() as f64);
    }

    Ok(valid_key_ids)
}

/// Handle fetch_key_solana request
pub async fn handle_fetch_key_solana(
    State(app_state): State<MyState>,
    headers: HeaderMap,
    Json(payload): Json<FetchKeySolanaRequest>,
) -> Result<Json<FetchKeySolanaResponse>, InternalError> {
    let metrics = &app_state.metrics;

    // Extract request ID for logging
    let req_id = headers
        .get("x-request-id")
        .map(|v| v.to_str().unwrap_or_default());

    println!("handle_fetch_key_solana req_id: {:?}", req_id);

    // Increment request counter
    metrics.requests.inc();

    // Check if the full node is fresh
    app_state.check_full_node_is_fresh(ALLOWED_STALENESS)?;

    // Check SDK version if provided in headers
    if let Some(sdk_version) = headers.get("x-seal-sdk-version") {
        if let Ok(version_str) = sdk_version.to_str() {
            // Using the appropriate method to validate SDK version
            if let Err(e) = app_state.validate_sdk_version(version_str) {
                metrics.observe_error(e.as_str());
                return Err(e);
            }
        }
    }

    debug!("Received fetch_key_solana request (req_id: {:?})", req_id);

    // Parse the Solana transaction from bytes
    let transaction = parse_transaction(&payload.ptb).tap_err(|e| {
        warn!(
            "Failed to parse transaction: {:?} (req_id: {:?})",
            e, req_id
        );
        metrics.observe_error(e.as_str());
    })?;

    println!("Transaction parsed successfully (req_id: {:?})", req_id);

    // check request for its signature
    // then certificate for its signature
    // then check policy
    // then extract key ids
    let key_ids = check_request_solana(
        &transaction,
        &payload.enc_key,
        &payload.enc_verification_key,
        &payload.request_signature,
        &payload.certificate,
        Some(metrics),
        req_id,
        &app_state.server,
    )
    .await
    .tap_err(|e| {
        warn!("Request check failed: {:?} (req_id: {:?})", e, req_id);
        metrics.observe_error(e.as_str());
    })?;

    println!("Key IDs extracted count: {:?}", key_ids.len());

    // Create response with encrypted keys
    let response = create_response_solana(&app_state.server, &key_ids, &payload.enc_key);

    println!(
        "Response created with {} keys",
        response.decryption_keys.len()
    );
    info!("Fetch key request successful (req_id: {:?})", req_id);

    Ok(Json(response))
}
