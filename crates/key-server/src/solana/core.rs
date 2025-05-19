use crate::errors::InternalError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
use bincode;
use crypto::create_full_id;
use fastcrypto::encoding::{Base64, Encoding};
use serde_json::{json, Value};
use tracing::{debug, warn};
use ureq;
use crate::solana::constants::{SEAL_APPROVE_DISCRIMINATOR, SOLANA_RPC_ENDPOINT};

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

/// Extract program ID from transaction's first instruction
pub fn get_first_program_id_from_transaction(transaction: &Transaction) -> Result<&Pubkey, InternalError> {
    // return the program id of the first instruction
    let program_id = transaction
        .message
        .account_keys
        .get(transaction.message.instructions[0].program_id_index as usize)
        .unwrap();

    Ok(program_id)
}

/// Helper function to check if an instruction is a Seal program instruction
fn check_instruction(
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
pub fn get_key_ids_from_transaction(
    transaction: &Transaction,
    program_id: &Pubkey,
) -> Result<Vec<Vec<u8>>, InternalError> {
    // Look for instructions that call our Seal program
    let mut key_ids = Vec::new();
    let account_keys = &transaction.message.account_keys;

    for ix in &transaction.message.instructions {
        if check_instruction(ix, program_id, account_keys) {
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

/// Simulate transaction on Solana
async fn simulate_transaction(transaction: &Transaction) -> Result<Value, InternalError> {
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
            warn!("Solana RPC request failed: {:?}", e);
            InternalError::Failure
        })?;

    let response_text = response.into_string().map_err(|e| {
        warn!("Failed to parse Solana RPC response: {:?}", e);
        InternalError::Failure
    })?;

    serde_json::from_str(&response_text).map_err(|e| {
        warn!("Failed to parse Solana RPC response: {:?}", e);
        InternalError::Failure
    })
}

// Constants for program return values
const PROGRAM_RETURN_OK: &str = "AgAAAG9r"; // base64 encoded "ok"
const PROGRAM_RETURN_NOT_OK: &str = "BgAAAG5vdF9vaw=="; // base64 encoded "not_ok"

/// Parse a single program return log
fn parse_program_return_log(log_str: &str, program_id: &str) -> Option<bool> {
    // Extract the relevant part of the log
    let relevant_part = if log_str.starts_with("Program log: Program return:") {
        log_str.trim_start_matches("Program log: Program return:").trim()
    } else if log_str.starts_with("Program return:") {
        log_str.trim_start_matches("Program return:").trim()
    } else {
        return None;
    };

    // Split into program ID and return value
    let parts: Vec<&str> = relevant_part.split_whitespace().collect();
    if parts.len() < 2 {
        debug!("Invalid program return log format: {}", log_str);
        return None;
    }

    // Check if this log is for our program
    let program_id_found = parts[0..parts.len()-1].iter().any(|&p| p == program_id);
    if !program_id_found {
        return None;
    }

    // Parse the return value
    let return_value = parts.last().unwrap();
    match *return_value {
        PROGRAM_RETURN_OK => Some(true),
        PROGRAM_RETURN_NOT_OK => Some(false),
        _ => {
            debug!(
                "Unexpected program return value: {} in log: {}",
                return_value, log_str
            );
            None
        }
    }
}

/// Process simulation result and extract outcomes
fn process_simulation_result(
    response_json: &Value,
    program_id: &str,
) -> Result<Vec<bool>, InternalError> {
    let result_value = response_json
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or_else(|| {
            warn!("Missing 'result.value' in Solana simulation result");
            InternalError::Failure
        })?;

    if let Some(err) = result_value.get("err") {
        if !err.is_null() {
            println!("### Solana simulation returned error: {:?}", err);
            if let Some(logs) = result_value.get("logs") {
                println!("### Program logs on error: {:?}", logs);
            }
            debug!("Solana simulation returned error: {:?}", err);
            return Err(InternalError::NoAccess);
        }
    }

    let logs = result_value
        .get("logs")
        .and_then(|l| l.as_array())
        .ok_or_else(|| {
            warn!("Missing or invalid logs array in Solana simulation result");
            InternalError::Failure
        })?;

    debug!("Processing {} simulation logs for program: {}", logs.len(), program_id);

    // Process all logs and collect valid outcomes
    let outcomes: Vec<bool> = logs
        .iter()
        .filter_map(|log_value| {
            log_value
                .as_str()
                .and_then(|log_str| parse_program_return_log(log_str, program_id))
        })
        .collect();

    if outcomes.is_empty() {
        debug!("No valid program return logs found for program: {}", program_id);
    } else {
        debug!(
            "Found {} valid program return logs for program: {}",
            outcomes.len(),
            program_id
        );
    }

    Ok(outcomes)
}

/// Check policy via transaction simulation
pub async fn check_seal_approve(
    transaction: &Transaction,
    program_id: &Pubkey,
    certificate_user_pubkey: &Pubkey,
) -> Result<Vec<Vec<u8>>, InternalError> {
    debug!(
        "check_seal_approve - program_id: {:?}, certificate_user_pubkey: {:?}",
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

    // TODO - should we require pubkey of the certificate/sessionKey signer?

    // Check if any instruction in the transaction calls the program as approved in the certificate
    let seal_instruction = transaction
        .message
        .instructions
        .iter()
        .find(|ix| check_instruction(ix, program_id, account_keys));

    if seal_instruction.is_none() {
        return Err(InternalError::InvalidPTB(
            "No Seal program instruction found".to_string(),
        ));
    }

    // TODO - should we require all instructions in the transaction to call the program?
    println!("### starting transaction simulation ###");

    // Simulate transaction and process results
    let response_json = simulate_transaction(transaction).await?;
    let program_id_for_log = program_id.to_string();
    let seal_approve_outcomes = process_simulation_result(&response_json, &program_id_for_log)?;

    println!("### simulation seal_approve_outcomes: {:?}", seal_approve_outcomes);

    // Extract key IDs from transaction's instructions
    let key_ids = get_key_ids_from_transaction(transaction, program_id)?;

    println!("### seal_approve_outcomes: {:?}, key_ids: {:?}", seal_approve_outcomes.len(), key_ids.len());

    // Filter valid key IDs based on outcomes
    let valid_key_ids: Vec<Vec<u8>> = seal_approve_outcomes
        .iter()
        .enumerate()
        .filter(|(_, &outcome)| outcome)
        .map(|(i, _)| key_ids[i].clone())
        .collect();
    
    if seal_approve_outcomes.is_empty() {
        debug!(
            "No 'Program return:' logs from program {} found with expected 'ok' or 'not_ok'",
            program_id_for_log
        );
        return Err(InternalError::NoAccess);
    }

    println!("### valid_key_ids: {:?}", valid_key_ids.len());
    Ok(valid_key_ids)
}
