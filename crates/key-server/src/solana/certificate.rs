use crate::errors::InternalError;
use chrono::{DateTime, Utc};
use tap::TapFallible;
use tracing::debug;

use crate::solana::types::Certificate;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

/// Make a message for the certificate/sessionKey
/// program_id is from the first instruction of the transaction passed in ptb
pub fn message_for_certificate(certificate: &Certificate, program_id: String) -> String {
    let message = format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        program_id,
        certificate.ttl_min,
        DateTime::<Utc>::from_timestamp((certificate.creation_time / 1000) as i64, 0)
            .expect("valid timestamp"),
        certificate.session_vk,
    );

    message
}

/// Verify a Solana message signature
pub fn verify_signature(
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

/// Check if certificate is valid
/// program_id is from the first instruction of the transaction passed in ptb
pub fn check_certificate(
    certificate: &Certificate,
    program_id: String,
) -> Result<(), InternalError> {
    // Check if certificate is expired
    let now = chrono::Utc::now().timestamp_millis() as u64;
    if now > certificate.creation_time + ((certificate.ttl_min as u64) * 60 * 1000) {
        return Err(InternalError::InvalidCertificate);
    }

    let message = message_for_certificate(certificate, program_id);
   
    // verify signature
    verify_signature(
        message.as_bytes(),
        &certificate.signature,
        &certificate.user,
    )
    .tap_err(|e| {
        println!("### Certificate Signature verification failed: {:?}", e);
        debug!(
            "Certificate signature invalid: {:?}",
            e
        )
    })
}
