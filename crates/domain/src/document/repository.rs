//! Document repository traits

use async_trait::async_trait;

use super::document::Document;
use super::document_update::DocumentUpdate;
use super::value_objects::DocumentId;
use crate::workspace::WorkspaceId;

/// Document repository trait
#[async_trait]
pub trait DocumentRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find document by ID
    async fn find_by_id(&self, id: DocumentId) -> Result<Option<Document>, Self::Error>;

    /// Find all documents in a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error>;

    /// Find documents by parent
    async fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>, Self::Error>;

    /// Find root documents (no parent) in a workspace
    async fn find_roots_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error>;

    /// Find documents needing DEK rotation (Phase 3+: device revocation → DEK rotation)
    async fn find_needing_dek_rotation(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error>;

    /// Check if slug exists in workspace
    async fn slug_exists(&self, workspace_id: WorkspaceId, slug: &str)
    -> Result<bool, Self::Error>;

    /// Save document
    async fn save(&self, document: &Document) -> Result<(), Self::Error>;

    /// Delete document
    async fn delete(&self, id: DocumentId) -> Result<(), Self::Error>;
}

/// Document update repository trait
#[async_trait]
pub trait DocumentUpdateRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find updates by document ID
    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentUpdate>, Self::Error>;

    /// Find updates by document ID after a sequence number
    async fn find_by_document_id_after_seq(
        &self,
        document_id: DocumentId,
        after_seq: i64,
    ) -> Result<Vec<DocumentUpdate>, Self::Error>;

    /// Find update by hash (for idempotency)
    async fn find_by_hash(&self, update_hash: &str) -> Result<Option<DocumentUpdate>, Self::Error>;

    /// Get latest sequence number for a document (Phase 3+: update compaction)
    async fn get_latest_seq(&self, document_id: DocumentId) -> Result<Option<i64>, Self::Error>;

    /// Get the hash of the latest update for a document (for hash chain validation)
    async fn get_latest_update_hash(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<String>, Self::Error>;

    /// Save update atomically (assigns seq, verifies chain)
    /// Returns (id, seq) on success
    async fn save(&self, update: &DocumentUpdate) -> Result<(i64, i64), Self::Error>;

    /// Check if an error represents a duplicate update_hash violation
    fn is_duplicate_hash(&self, err: &Self::Error) -> bool;

    /// Check if an error represents a chain mismatch (prev_update_hash didn't match latest)
    fn is_chain_mismatch(&self, err: &Self::Error) -> bool;

    /// Delete updates by document ID
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;

    /// Delete updates before a sequence number (Phase 3+: update compaction)
    async fn delete_before_seq(
        &self,
        document_id: DocumentId,
        before_seq: i64,
    ) -> Result<u64, Self::Error>;
}


