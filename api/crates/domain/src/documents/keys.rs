//! E2EE key types for documents

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::identity::keys::KdfParams;

/// Document encrypted key (DEK encrypted with workspace KEK)
#[derive(Debug, Clone)]
pub struct DocumentEncryptedKey {
    pub document_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Share encrypted key (DEK encrypted for share access)
#[derive(Debug, Clone)]
pub struct ShareEncryptedKey {
    pub share_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    /// Salt for password-protected shares (optional)
    pub salt: Option<Vec<u8>>,
    /// KDF params for password-protected shares (optional)
    pub kdf_params: Option<KdfParams>,
    pub created_at: DateTime<Utc>,
}

impl ShareEncryptedKey {
    pub fn is_password_protected(&self) -> bool {
        self.salt.is_some()
    }
}

/// Public document content (plaintext for published documents)
#[derive(Debug, Clone)]
pub struct PublicDocumentContent {
    pub document_id: Uuid,
    pub content: String,
    pub title: String,
    pub content_hash: String,
    pub updated_at: DateTime<Utc>,
}

/// Encrypted tag index entry (deterministic encryption for searchable tags)
#[derive(Debug, Clone)]
pub struct EncryptedTagIndex {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub document_id: Uuid,
    pub encrypted_tag: Vec<u8>,
    pub created_at: DateTime<Utc>,
}
