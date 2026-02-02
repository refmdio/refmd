//! DocumentSnapshot entity

use chrono::{DateTime, Utc};

use crate::encryption::DeviceId;
use super::value_objects::DocumentId;

/// Document snapshot
#[derive(Debug, Clone)]
pub struct DocumentSnapshot {
    pub id: i64,
    pub document_id: DocumentId,
    pub version: i64,
    pub snapshot_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub signature: Vec<u8>,
    pub author_device_id: DeviceId,
    pub seq_at_snapshot: i64,
    pub created_at: DateTime<Utc>,
}

impl DocumentSnapshot {
    /// Create a new document snapshot
    pub fn new(
        document_id: DocumentId,
        version: i64,
        snapshot_data: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i32,
        signature: Vec<u8>,
        author_device_id: DeviceId,
        seq_at_snapshot: i64,
    ) -> Self {
        Self {
            id: 0, // Will be set by database
            document_id,
            version,
            snapshot_data,
            nonce,
            key_version,
            signature,
            author_device_id,
            seq_at_snapshot,
            created_at: Utc::now(),
        }
    }
}
