use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

/// Encrypted tag entry for a document
#[derive(Debug, Clone)]
pub struct EncryptedTagEntry {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub document_id: Uuid,
    pub encrypted_tag: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Summary of encrypted tags with occurrence count
#[derive(Debug, Clone)]
pub struct EncryptedTagSummary {
    pub encrypted_tag: Vec<u8>,
    pub count: i64,
}

#[async_trait]
pub trait EncryptedTagRepository: Send + Sync {
    /// List all unique encrypted tags in a workspace with their counts
    async fn list_encrypted_tags(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<EncryptedTagSummary>>;

    /// List encrypted tags for a specific document
    async fn list_document_encrypted_tags(
        &self,
        document_id: Uuid,
    ) -> PortResult<Vec<EncryptedTagEntry>>;

    /// Replace all encrypted tags for a document
    async fn replace_document_encrypted_tags(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        encrypted_tags: &[Vec<u8>],
    ) -> PortResult<Vec<EncryptedTagEntry>>;

    /// Find documents by encrypted tag (deterministic encryption allows exact match)
    async fn find_documents_by_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: &[u8],
    ) -> PortResult<Vec<Uuid>>;

    /// Find a specific encrypted tag with its count (for filtering)
    async fn find_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: &[u8],
    ) -> PortResult<Vec<EncryptedTagSummary>>;

    /// Delete all encrypted tags for a document
    async fn delete_document_encrypted_tags(&self, document_id: Uuid) -> PortResult<()>;
}
