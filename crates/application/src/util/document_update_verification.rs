//! Document update hash and signature verification utilities.
//!
//! Extracted from `create_update.rs` for reuse and testability.

use domain::document::DocumentId;
use domain::encryption::DeviceId;
use domain::signature::{SignatureAction, build_signature_message};
use serde::Serialize;
use thiserror::Error;

/// Error from update hash verification.
#[derive(Debug, Error)]
#[error("invalid update hash")]
pub struct UpdateHashError;

/// Error from document update signature verification.
#[derive(Debug, Error)]
#[error("invalid document update signature")]
pub struct DocumentUpdateSignatureError;

/// Verify that `BLAKE3(JCS({fields}))` matches the claimed `update_hash`.
#[allow(clippy::too_many_arguments)]
pub fn verify_update_hash(
    document_id: DocumentId,
    update_data: &[u8],
    nonce: &[u8],
    key_version: i32,
    update_hash: &str,
    prev_update_hash: Option<&str>,
    author_device_id: DeviceId,
    timestamp: i64,
) -> Result<(), UpdateHashError> {
    #[derive(Serialize)]
    struct UpdateHashInput<'a> {
        created_by_device_id: &'a str,
        document_id: &'a str,
        encrypted_content: &'a str,
        key_version: i64,
        nonce: &'a str,
        prev_update_hash: Option<&'a str>,
        timestamp: i64,
    }

    let encrypted_content_b64 = base64_url::encode(update_data);
    let nonce_b64 = base64_url::encode(nonce);

    let input = UpdateHashInput {
        created_by_device_id: &author_device_id.to_string(),
        document_id: &document_id.to_string(),
        encrypted_content: &encrypted_content_b64,
        key_version: key_version as i64,
        nonce: &nonce_b64,
        prev_update_hash,
        timestamp,
    };

    let canonical = {
        let value = serde_json::to_value(&input).map_err(|_| UpdateHashError)?;
        let sorted =
            domain::signature::sort_value_public(value).map_err(|_| UpdateHashError)?;
        serde_json::to_vec(&sorted).map_err(|_| UpdateHashError)?
    };
    let computed_hash = blake3::hash(&canonical);
    let computed_hash_b64 = base64_url::encode(computed_hash.as_bytes());
    if computed_hash_b64 != update_hash {
        return Err(UpdateHashError);
    }

    Ok(())
}

/// Verify Ed25519 signature over document update metadata using JCS.
pub fn verify_document_update_signature(
    signing_public_key: &[u8],
    signature: &[u8],
    document_id: &str,
    update_hash: &str,
    prev_update_hash: Option<&str>,
    key_version: i64,
    timestamp: i64,
) -> Result<(), DocumentUpdateSignatureError> {
    #[derive(Serialize)]
    struct DocumentUpdatePayload<'a> {
        document_id: &'a str,
        key_version: i64,
        prev_update_hash: Option<&'a str>,
        timestamp: i64,
        update_hash: &'a str,
    }

    let message = build_signature_message(
        SignatureAction::DocumentUpdate,
        &DocumentUpdatePayload {
            document_id,
            key_version,
            prev_update_hash,
            timestamp,
            update_hash,
        },
    )
    .map_err(|_| DocumentUpdateSignatureError)?;

    crate::util::signature_verification::verify_ed25519_signature(
        signing_public_key,
        signature,
        &message,
    )
    .map_err(|_| DocumentUpdateSignatureError)
}
