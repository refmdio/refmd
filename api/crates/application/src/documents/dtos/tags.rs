use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TagItemDto {
    pub name: String,
    pub count: i64,
}

/// Encrypted tag item with Base64-encoded tag
#[derive(Debug, Clone)]
pub struct EncryptedTagItemDto {
    pub encrypted_tag: Vec<u8>,
    pub count: i64,
}

/// Encrypted tag entry for a document
#[derive(Debug, Clone)]
pub struct EncryptedTagEntryDto {
    pub id: Uuid,
    pub encrypted_tag: Vec<u8>,
    pub created_at: DateTime<Utc>,
}
