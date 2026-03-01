//! WebSocket envelope signature verification
//!
//! Phase 4B uses a different signature protocol from Phase 4A HTTP API.
//! WS envelopes use domain-separated prefixes ("refmd_snapshot", "refmd_update",
//! "refmd_ephemeral") and sign over JCS({ nonce, ciphertext, publicData: base64url(JCS(publicData)) }).

use application::jcs::{SignatureError, sort_value_public};
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Domain-separation prefixes for WS envelope signatures
pub const PREFIX_SNAPSHOT: &str = "refmd_snapshot";
pub const PREFIX_UPDATE: &str = "refmd_update";
pub const PREFIX_EPHEMERAL: &str = "refmd_ephemeral";
/// Session proof prefix (used client-side within encrypted ephemeral payloads)
pub const PREFIX_EPHEMERAL_SESSION_PROOF: &str = "refmd_ephemeral_session_proof";

#[derive(Debug, Error)]
pub enum WsSignatureError {
    #[error("invalid signing public key")]
    InvalidPublicKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("JCS canonicalization error: {0}")]
    Jcs(#[from] SignatureError),
    #[error("base64url decode error: {0}")]
    Base64(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Verify a WebSocket envelope signature.
///
/// The signed message is: `prefix || JCS({ ciphertext, nonce, publicData: base64url(JCS(publicData)) })`
pub fn verify_ws_envelope_signature(
    prefix: &str,
    ciphertext: &str,
    nonce: &str,
    public_data: &Value,
    signature_b64: &str,
    signing_pub_key_b64: &str,
) -> Result<(), WsSignatureError> {
    // Decode public key
    let pub_key_bytes = base64_url::decode(signing_pub_key_b64)
        .map_err(|e| WsSignatureError::Base64(e.to_string()))?;
    let pub_key_array: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| WsSignatureError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_array).map_err(|_| WsSignatureError::InvalidPublicKey)?;

    // Decode signature
    let sig_bytes = base64_url::decode(signature_b64)
        .map_err(|e| WsSignatureError::Base64(e.to_string()))?;
    let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
        .try_into()
        .map_err(|_| WsSignatureError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);

    // Build signed message: prefix || JCS({ ciphertext, nonce, publicData: base64url(JCS(publicData)) })
    let message = build_ws_signature_message(prefix, ciphertext, nonce, public_data)?;

    // Verify
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| WsSignatureError::VerificationFailed)
}

/// Build the message bytes that were signed.
///
/// `prefix || JCS({ ciphertext, nonce, publicData: base64url(JCS(publicData)) })`
fn build_ws_signature_message(
    prefix: &str,
    ciphertext: &str,
    nonce: &str,
    public_data: &Value,
) -> Result<Vec<u8>, WsSignatureError> {
    // 1. Canonicalize publicData
    let sorted_public_data = sort_value_public(public_data.clone())?;
    let public_data_jcs = serde_json::to_vec(&sorted_public_data)?;
    let public_data_b64 = base64_url::encode(&public_data_jcs);

    // 2. Build the envelope object: { ciphertext, nonce, publicData: base64url(JCS(publicData)) }
    let mut envelope: BTreeMap<String, Value> = BTreeMap::new();
    envelope.insert("ciphertext".to_string(), Value::String(ciphertext.to_string()));
    envelope.insert("nonce".to_string(), Value::String(nonce.to_string()));
    envelope.insert("publicData".to_string(), Value::String(public_data_b64));

    let envelope_jcs = serde_json::to_vec(&envelope)?;

    // 3. prefix || envelope_jcs
    let mut message = prefix.as_bytes().to_vec();
    message.extend_from_slice(&envelope_jcs);

    Ok(message)
}
