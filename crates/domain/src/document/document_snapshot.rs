//! DocumentSnapshot entity

use chrono::{DateTime, Utc};

use super::value_objects::DocumentId;
use crate::encryption::DeviceId;

/// Parameters for creating a new document snapshot
#[derive(Debug, Clone)]
pub struct NewDocumentSnapshotParams {
    pub document_id: DocumentId,
    pub version: i64,
    pub snapshot_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub signature: Vec<u8>,
    pub author_device_id: DeviceId,
    pub seq_at_snapshot: i64,
}

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
    pub fn new(params: NewDocumentSnapshotParams) -> Self {
        Self {
            id: 0, // Will be set by database
            document_id: params.document_id,
            version: params.version,
            snapshot_data: params.snapshot_data,
            nonce: params.nonce,
            key_version: params.key_version,
            signature: params.signature,
            author_device_id: params.author_device_id,
            seq_at_snapshot: params.seq_at_snapshot,
            created_at: Utc::now(),
        }
    }
}
