//! DocumentUpdate entity

use chrono::{DateTime, Utc};

use crate::encryption::DeviceId;
use super::value_objects::DocumentId;

/// Document update (CRDT update log)
#[derive(Debug, Clone)]
pub struct DocumentUpdate {
    pub id: i64,
    pub document_id: DocumentId,
    pub seq: i64,
    pub update_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub update_hash: String,
    pub prev_update_hash: Option<String>,
    pub signature: Vec<u8>,
    pub author_device_id: DeviceId,
    pub timestamp: i64,
    pub created_at: DateTime<Utc>,
}

impl DocumentUpdate {
    /// Create a new document update
    pub fn new(
        document_id: DocumentId,
        seq: i64,
        update_data: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i32,
        update_hash: String,
        prev_update_hash: Option<String>,
        signature: Vec<u8>,
        author_device_id: DeviceId,
        timestamp: i64,
    ) -> Self {
        Self {
            id: 0, // Will be set by database
            document_id,
            seq,
            update_data,
            nonce,
            key_version,
            update_hash,
            prev_update_hash,
            signature,
            author_device_id,
            timestamp,
            created_at: Utc::now(),
        }
    }
}
