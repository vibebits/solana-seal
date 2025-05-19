use crate::errors::InternalError;
use crate::metrics::Metrics;
use crate::types::{ElGamalPublicKey, ElgamalVerificationKey};
use crate::solana::types::{FetchKeyRequest, FetchKeyResponse, DecryptionKey, Certificate};
use crate::solana::core::{parse_transaction, get_first_program_id_from_transaction, check_seal_approve};
use crate::solana::request::{verify_request_signature};
use crate::MyState;
use crate::ALLOWED_STALENESS;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use crypto::elgamal::encrypt;
use crypto::ibe::extract;
use fastcrypto::ed25519::{Ed25519Signature};
use rand::thread_rng;
use solana_sdk::transaction::Transaction;
use std::time::Instant;
use tap::tap::TapFallible;
use tracing::{debug, info, warn};
use crate::solana::certificate::{check_certificate};

/// Create response with encrypted keys
fn create_response(
    server: &crate::Server,
    key_ids: &[Vec<u8>],
    enc_key: &ElGamalPublicKey,
) -> FetchKeyResponse {
    let mut decryption_keys = Vec::new();
    let mut rng = thread_rng();

    for id in key_ids {
        // Extract a key based on the ID
        let derived_key = extract(&server.master_key, id);

        // Encrypt the derived key with user's key
        let encrypted_key = encrypt(&mut rng, &derived_key, enc_key);

        println!("extract key for id: {:?}", id);
        // Add to response
        decryption_keys.push(DecryptionKey {
            id: id.clone(),
            encrypted_key,
        });
    }

    FetchKeyResponse { decryption_keys }
}

/// This is the overall main function
/// It checks the request, certificate, and policy
/// It returns the key ids
async fn check_request(
    transaction: &Transaction,
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
    request_signature: &Ed25519Signature,
    certificate: &Certificate,
    metrics: Option<&Metrics>,
    req_id: Option<&str>,
    _server: &crate::Server,
) -> Result<Vec<Vec<u8>>, InternalError> {
    let _start = Instant::now();

    // Verify request signature (signs over transaction + encryption keys)
    verify_request_signature(
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

    // Extract program ID from transaction (of 1 or more instructions)
    // we get the program id from the first instruction
    let program_id = get_first_program_id_from_transaction(transaction)?;
    println!("Program ID: {}", program_id.to_string());

    // Check certificate validity
    check_certificate(certificate, program_id.to_string())?;

    println!(
        "Certificate validity checked successfully (req_id: {:?})",
        req_id
    );

    // Check policy by simulating the transaction
    let valid_key_ids = check_seal_approve(transaction, &program_id, &certificate.user).await?;

    println!("Policy checked successfully (req_id: {:?})", req_id);

    println!("Key IDs count: {:?}", valid_key_ids.len());
    println!("Key IDs extracted successfully (req_id: {:?})", req_id);

    // Report metrics if available - using proper field name
    if let Some(m) = metrics {
        m.requests_per_number_of_ids.observe(valid_key_ids.len() as f64);
    }

    Ok(valid_key_ids)
}

/// Handle fetch_key request
pub async fn handle_fetch_key(
    State(app_state): State<MyState>,
    headers: HeaderMap,
    Json(payload): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, InternalError> {
    let metrics = &app_state.metrics;

    // Extract request ID for logging
    let req_id = headers
        .get("x-request-id")
        .map(|v| v.to_str().unwrap_or_default());

    println!("handle_fetch_key req_id: {:?}", req_id);

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

    debug!("Received /v1/fetch_key_solana request (req_id: {:?})", req_id);

    // Parse the Solana transaction from bytes
    let transaction = parse_transaction(&payload.ptb).tap_err(|e| {
        warn!(
            "Failed to parse transaction: {:?} (req_id: {:?})",
            e, req_id
        );
        metrics.observe_error(e.as_str());
    })?;

    println!("Transaction parsed successfully (req_id: {:?})", req_id);

    // check request for its signature (also get program_id)
    // then checkcertificate for its validity and signature (with program_id from request tx's 1st ix)
    // then check policy (seal_approve)
    // then extract key ids
    let key_ids = check_request(
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

    // Create response with keys
    let response = create_response(&app_state.server, &key_ids, &payload.enc_key);

    println!(
        "Response created with {} keys",
        response.decryption_keys.len()
    );
    info!("Fetch key request successful (req_id: {:?})", req_id);

    Ok(Json(response))
}
