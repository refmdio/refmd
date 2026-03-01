//! DocumentUpdate entity (clock-based)

use chrono::{DateTime, Utc};

use super::value_objects::{DocumentId, DocumentSnapshotId};

/// Parameters for creating a new document update
#[derive(Debug, Clone)]
pub struct NewDocumentUpdateParams {
    pub document_id: DocumentId,
    /// Encrypted Yjs update binary
    pub update_data: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: Vec<u8>,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Content-addressable hash: BLAKE3(JCS({fields})) base64url
    pub update_hash: String,
    /// Ed25519 WS envelope signature (see collaboration.md for signing scheme)
    pub signature: Vec<u8>,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
    /// Snapshot this update belongs to
    pub snapshot_id: DocumentSnapshotId,
    /// Per-device monotonic clock (assigned by client, verified by DB)
    pub clock: i32,
    /// Device signing public key (base64url)
    pub device_signing_pub_key: String,
}

/// Document update (CRDT update log, clock-based)
///
/// Represents an encrypted Yjs update stored in the database.
/// Ordered by per-device monotonic clock within a snapshot.
#[derive(Debug, Clone)]
pub struct DocumentUpdate {
    pub id: i64,
    pub document_id: DocumentId,
    /// Encrypted Yjs update binary
    pub update_data: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: Vec<u8>,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Content-addressable hash for idempotency
    pub update_hash: String,
    /// Ed25519 WS envelope signature (see collaboration.md for signing scheme)
    pub signature: Vec<u8>,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
    /// Snapshot this update belongs to
    pub snapshot_id: DocumentSnapshotId,
    /// Per-device monotonic clock value
    pub clock: i32,
    /// Global version (monotonic across all devices in a snapshot)
    pub version: i64,
    /// Device signing public key (base64url)
    pub device_signing_pub_key: String,
    pub created_at: DateTime<Utc>,
}

impl DocumentUpdate {
    /// Create a new document update
    pub fn new(params: NewDocumentUpdateParams) -> Self {
        Self {
            id: 0,           // Will be set by database
            document_id: params.document_id,
            update_data: params.update_data,
            nonce: params.nonce,
            key_version: params.key_version,
            update_hash: params.update_hash,
            signature: params.signature,
            timestamp: params.timestamp,
            snapshot_id: params.snapshot_id,
            clock: params.clock,
            version: 0,      // Will be set by database
            device_signing_pub_key: params.device_signing_pub_key,
            created_at: Utc::now(),
        }
    }
}
