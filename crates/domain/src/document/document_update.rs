//! DocumentUpdate entity

use chrono::{DateTime, Utc};

use super::value_objects::DocumentId;
use crate::encryption::DeviceId;

/// Parameters for creating a new document update (Phase 1C MVP)
///
/// Phase 2 fields (update_hash, signature, author_device_id) are optional.
#[derive(Debug, Clone)]
pub struct NewDocumentUpdateParams {
    pub document_id: DocumentId,
    pub seq: i64,
    pub update_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    /// Phase 2: Content-addressable hash for idempotency
    pub update_hash: Option<String>,
    pub prev_update_hash: Option<String>,
    /// Phase 2: Ed25519 signature
    pub signature: Option<Vec<u8>>,
    /// Phase 2: Device that authored this update
    pub author_device_id: Option<DeviceId>,
    pub timestamp: i64,
}

/// Document update (CRDT update log)
///
/// Represents an encrypted Yjs update stored in the database.
/// Phase 2 fields for signing and hash chain are nullable for MVP.
#[derive(Debug, Clone)]
pub struct DocumentUpdate {
    pub id: i64,
    pub document_id: DocumentId,
    pub seq: i64,
    /// Encrypted Yjs update binary
    pub update_data: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: Vec<u8>,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Phase 2: Content-addressable hash for idempotency
    pub update_hash: Option<String>,
    pub prev_update_hash: Option<String>,
    /// Phase 2: Ed25519 signature
    pub signature: Option<Vec<u8>>,
    /// Phase 2: Device that authored this update
    pub author_device_id: Option<DeviceId>,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
    pub created_at: DateTime<Utc>,
}

impl DocumentUpdate {
    /// Create a new document update
    pub fn new(params: NewDocumentUpdateParams) -> Self {
        Self {
            id: 0, // Will be set by database
            document_id: params.document_id,
            seq: params.seq,
            update_data: params.update_data,
            nonce: params.nonce,
            key_version: params.key_version,
            update_hash: params.update_hash,
            prev_update_hash: params.prev_update_hash,
            signature: params.signature,
            author_device_id: params.author_device_id,
            timestamp: params.timestamp,
            created_at: Utc::now(),
        }
    }
}
