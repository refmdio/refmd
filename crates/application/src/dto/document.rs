use chrono::{DateTime, Utc};

use domain::document::{Document, DocumentUpdate};
use domain::document::DocumentId;
use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::workspace::WorkspaceId;

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

/// DTO for DocumentUpdate entity
#[derive(Debug, Clone)]
pub struct DocumentUpdateDto {
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

impl From<DocumentUpdate> for DocumentUpdateDto {
    fn from(u: DocumentUpdate) -> Self {
        Self {
            id: u.id,
            document_id: u.document_id,
            seq: u.seq,
            update_data: u.update_data,
            nonce: u.nonce,
            key_version: u.key_version,
            update_hash: u.update_hash,
            prev_update_hash: u.prev_update_hash,
            signature: u.signature,
            author_device_id: u.author_device_id,
            timestamp: u.timestamp,
            created_at: u.created_at,
        }
    }
}
