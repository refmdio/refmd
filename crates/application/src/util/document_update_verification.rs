//! Document hash computation utilities.
//!
//! Server-side hash computation for document updates and snapshot proofs.

use domain::document::{DocumentId, DocumentSnapshotId};
use domain::signature::SignatureError;
use serde::Serialize;

/// Compute `BLAKE3(JCS({fields}))` for a document update.
/// Client sends update_hash; server re-computes and verifies match.
pub fn compute_update_hash(
    document_id: DocumentId,
    update_data: &[u8],
    nonce: &[u8],
    key_version: i32,
    ref_snapshot_id: DocumentSnapshotId,
    clock: i32,
    device_signing_pub_key: &str,
    timestamp: i64,
) -> Result<String, SignatureError> {
    #[derive(Serialize)]
    struct UpdateHashInput<'a> {
        clock: i64,
        device_signing_pub_key: &'a str,
        document_id: &'a str,
        encrypted_content: &'a str,
        key_version: i64,
        nonce: &'a str,
        ref_snapshot_id: &'a str,
        timestamp: i64,
    }

    let encrypted_content_b64 = base64_url::encode(update_data);
    let nonce_b64 = base64_url::encode(nonce);

    let input = UpdateHashInput {
        clock: clock as i64,
        device_signing_pub_key,
        document_id: &document_id.to_string(),
        encrypted_content: &encrypted_content_b64,
        key_version: key_version as i64,
        nonce: &nonce_b64,
        ref_snapshot_id: &ref_snapshot_id.to_string(),
        timestamp,
    };

    let canonical = {
        let value = serde_json::to_value(&input)?;
        let sorted = domain::signature::sort_value_public(value)?;
        serde_json::to_vec(&sorted)?
    };
    let computed_hash = blake3::hash(&canonical);
    Ok(base64_url::encode(computed_hash.as_bytes()))
}

/// Compute `parentSnapshotProof = BLAKE3(JCS({ ciphertext_hash, parent_proof, snapshot_id }))`.
///
/// Per ADR-015 / collaboration.md: chain hash proves snapshot ancestry.
/// Keys use snake_case per codebase JCS convention (same as update_hash).
pub fn compute_parent_snapshot_proof(
    parent_ciphertext_hash: &str,
    grandparent_proof: &str,
    parent_snapshot_id: &str,
) -> Result<String, SignatureError> {
    #[derive(Serialize)]
    struct ProofInput<'a> {
        ciphertext_hash: &'a str,
        parent_proof: &'a str,
        snapshot_id: &'a str,
    }

    let input = ProofInput {
        ciphertext_hash: parent_ciphertext_hash,
        parent_proof: grandparent_proof,
        snapshot_id: parent_snapshot_id,
    };

    let canonical = {
        let value = serde_json::to_value(&input)?;
        let sorted = domain::signature::sort_value_public(value)?;
        serde_json::to_vec(&sorted)?
    };
    let computed = blake3::hash(&canonical);
    Ok(base64_url::encode(computed.as_bytes()))
}
