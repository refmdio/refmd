use chrono::{DateTime, Utc};

use domain::document::{Document, DocumentSnapshot, DocumentSnapshotId, DocumentUpdate, SnapshotProof};
use domain::document::DocumentId;
use domain::identity::UserId;
use domain::workspace::WorkspaceId;
use std::collections::HashMap;

/// DTO for Document entity
#[derive(Debug, Clone)]
pub struct DocumentDto {
    pub id: DocumentId,
    pub workspace_id: WorkspaceId,
    pub parent_id: Option<DocumentId>,
    pub title: String,
    pub encrypted_title: Option<Vec<u8>>,
    pub encrypted_title_nonce: Option<Vec<u8>>,
    pub slug: String,
    pub path: Option<String>,
    pub doc_type: String,
    pub is_encrypted: bool,
    pub is_archived: bool,
    pub needs_dek_rotation: bool,
    pub min_dek_version: i32,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

impl From<Document> for DocumentDto {
    fn from(doc: Document) -> Self {
        let is_archived = doc.is_archived();
        let doc_type = doc.doc_type.as_str().to_string();
        Self {
            id: doc.id,
            workspace_id: doc.workspace_id,
            parent_id: doc.parent_id,
            title: doc.title,
            encrypted_title: doc.encrypted_title,
            encrypted_title_nonce: doc.encrypted_title_nonce,
            slug: doc.slug,
            path: doc.path,
            doc_type,
            is_encrypted: doc.is_encrypted,
            is_archived,
            needs_dek_rotation: doc.needs_dek_rotation,
            min_dek_version: doc.min_dek_version,
            created_by: doc.created_by,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            archived_at: doc.archived_at,
        }
    }
}

/// DTO for DocumentUpdate entity (clock-based)
#[derive(Debug, Clone)]
pub struct DocumentUpdateDto {
    pub id: i64,
    pub document_id: DocumentId,
    pub update_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub update_hash: String,
    pub signature: Vec<u8>,
    pub timestamp: i64,
    pub snapshot_id: DocumentSnapshotId,
    pub clock: i32,
    pub version: i64,
    pub device_signing_pub_key: String,
    pub public_data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl From<(DocumentUpdate, serde_json::Value)> for DocumentUpdateDto {
    fn from((u, public_data): (DocumentUpdate, serde_json::Value)) -> Self {
        Self {
            id: u.id,
            document_id: u.document_id,
            update_data: u.update_data,
            nonce: u.nonce,
            key_version: u.key_version,
            update_hash: u.update_hash,
            signature: u.signature,
            timestamp: u.timestamp,
            snapshot_id: u.snapshot_id,
            clock: u.clock,
            version: u.version,
            device_signing_pub_key: u.device_signing_pub_key,
            public_data,
            created_at: u.created_at,
        }
    }
}

/// DTO for DocumentSnapshot entity
#[derive(Debug, Clone)]
pub struct DocumentSnapshotDto {
    pub id: DocumentSnapshotId,
    pub document_id: DocumentId,
    pub latest_version: i64,
    pub data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub signature: Vec<u8>,
    pub ciphertext_hash: String,
    pub clocks: HashMap<String, i64>,
    pub parent_snapshot_update_clocks: HashMap<String, i64>,
    pub parent_snapshot_proof: String,
    pub created_by_device: String,
    pub public_data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl From<(DocumentSnapshot, serde_json::Value)> for DocumentSnapshotDto {
    fn from((s, public_data): (DocumentSnapshot, serde_json::Value)) -> Self {
        Self {
            id: s.id,
            document_id: s.document_id,
            latest_version: s.latest_version,
            data: s.data,
            nonce: s.nonce,
            key_version: s.key_version,
            signature: s.signature,
            ciphertext_hash: s.ciphertext_hash,
            clocks: s.clocks,
            parent_snapshot_update_clocks: s.parent_snapshot_update_clocks,
            parent_snapshot_proof: s.parent_snapshot_proof,
            created_by_device: s.created_by_device,
            public_data,
            created_at: s.created_at,
        }
    }
}

/// DTO for SnapshotProof (proof chain entry)
#[derive(Debug, Clone)]
pub struct SnapshotProofDto {
    pub snapshot_id: DocumentSnapshotId,
    pub ciphertext_hash: String,
    pub parent_snapshot_proof: String,
}

impl From<SnapshotProof> for SnapshotProofDto {
    fn from(p: SnapshotProof) -> Self {
        Self {
            snapshot_id: p.snapshot_id,
            ciphertext_hash: p.ciphertext_hash,
            parent_snapshot_proof: p.parent_snapshot_proof,
        }
    }
}
