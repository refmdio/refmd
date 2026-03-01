//! DocumentSnapshot entity (collaboration checkpoint)

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use super::value_objects::{DocumentId, DocumentSnapshotId};

/// Parameters for creating a new collaboration snapshot
#[derive(Debug, Clone)]
pub struct NewDocumentSnapshotParams {
    /// Client-generated snapshot ID (included in signed publicData)
    pub id: DocumentSnapshotId,
    pub document_id: DocumentId,
    pub latest_version: i64,
    /// Encrypted Yjs full state (ciphertext)
    pub data: Vec<u8>,
    /// 24-byte XChaCha20-Poly1305 nonce
    pub nonce: Vec<u8>,
    pub key_version: i32,
    /// Ed25519 WS envelope signature (see collaboration.md for signing scheme)
    pub signature: Vec<u8>,
    /// BLAKE3(ciphertext) base64url
    pub ciphertext_hash: String,
    /// Per-device clocks: { deviceSigningPubKey: clock }
    pub clocks: HashMap<String, i64>,
    /// Clocks of the parent snapshot's updates at time of snapshot creation
    pub parent_snapshot_update_clocks: HashMap<String, i64>,
    /// base64url(BLAKE3 chain hash)
    pub parent_snapshot_proof: String,
    /// Signing public key (base64url) of the device that created this snapshot
    pub created_by_device: String,
}

/// Collaboration snapshot (CRDT checkpoint)
///
/// Represents an encrypted full Yjs document state at a point in time.
/// Forms a proof chain via `parent_snapshot_proof`.
#[derive(Debug, Clone)]
pub struct DocumentSnapshot {
    pub id: DocumentSnapshotId,
    pub document_id: DocumentId,
    /// Highest version number among updates included in this snapshot
    pub latest_version: i64,
    /// Encrypted Yjs full state (ciphertext)
    pub data: Vec<u8>,
    /// 24-byte XChaCha20-Poly1305 nonce
    pub nonce: Vec<u8>,
    pub key_version: i32,
    /// Ed25519 WS envelope signature (see collaboration.md for signing scheme)
    pub signature: Vec<u8>,
    /// BLAKE3(ciphertext) base64url
    pub ciphertext_hash: String,
    /// Per-device clocks at snapshot creation: { deviceSigningPubKey: clock }
    pub clocks: HashMap<String, i64>,
    /// Clocks from the parent snapshot's update set
    pub parent_snapshot_update_clocks: HashMap<String, i64>,
    /// base64url(BLAKE3 chain hash) linking to parent snapshot
    pub parent_snapshot_proof: String,
    /// Signing public key (base64url) of the creating device
    pub created_by_device: String,
    pub created_at: DateTime<Utc>,
}

impl DocumentSnapshot {
    pub fn new(params: NewDocumentSnapshotParams) -> Self {
        Self {
            id: params.id,
            document_id: params.document_id,
            latest_version: params.latest_version,
            data: params.data,
            nonce: params.nonce,
            key_version: params.key_version,
            signature: params.signature,
            ciphertext_hash: params.ciphertext_hash,
            clocks: params.clocks,
            parent_snapshot_update_clocks: params.parent_snapshot_update_clocks,
            parent_snapshot_proof: params.parent_snapshot_proof,
            created_by_device: params.created_by_device,
            created_at: Utc::now(),
        }
    }

}

/// A link in the snapshot proof chain (used for delta sync ancestry verification)
#[derive(Debug, Clone)]
pub struct SnapshotProof {
    pub snapshot_id: DocumentSnapshotId,
    pub ciphertext_hash: String,
    pub parent_snapshot_proof: String,
}
