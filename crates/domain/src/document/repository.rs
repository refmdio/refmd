//! Document repository traits

use async_trait::async_trait;

use crate::workspace::WorkspaceId;
use super::document::Document;
use super::document_link::DocumentLink;
use super::document_snapshot::DocumentSnapshot;
use super::document_update::DocumentUpdate;
use super::snapshot_archive::DocumentSnapshotArchive;
use super::tag::{DocumentTag, Tag};
use super::value_objects::{DocumentId, DocumentLinkId, SnapshotArchiveId, TagId};

/// Document repository trait
#[async_trait]
pub trait DocumentRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find document by ID
    async fn find_by_id(&self, id: DocumentId) -> Result<Option<Document>, Self::Error>;

    /// Find document by workspace and slug
    async fn find_by_workspace_and_slug(
        &self,
        workspace_id: WorkspaceId,
        slug: &str,
    ) -> Result<Option<Document>, Self::Error>;

    /// Find all documents in a workspace
    async fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>, Self::Error>;

    /// Find documents by parent
    async fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>, Self::Error>;

    /// Find root documents (no parent) in a workspace
    async fn find_roots_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>, Self::Error>;

    /// Find documents needing DEK rotation
    async fn find_needing_dek_rotation(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>, Self::Error>;

    /// Check if slug exists in workspace
    async fn slug_exists(&self, workspace_id: WorkspaceId, slug: &str) -> Result<bool, Self::Error>;

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
    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentUpdate>, Self::Error>;

    /// Find updates by document ID after a sequence number
    async fn find_by_document_id_after_seq(
        &self,
        document_id: DocumentId,
        after_seq: i64,
    ) -> Result<Vec<DocumentUpdate>, Self::Error>;

    /// Find update by hash (for idempotency)
    async fn find_by_hash(&self, update_hash: &str) -> Result<Option<DocumentUpdate>, Self::Error>;

    /// Get latest sequence number for a document
    async fn get_latest_seq(&self, document_id: DocumentId) -> Result<Option<i64>, Self::Error>;

    /// Save update
    async fn save(&self, update: &DocumentUpdate) -> Result<i64, Self::Error>;

    /// Delete updates by document ID
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;

    /// Delete updates before a sequence number (for compaction)
    async fn delete_before_seq(&self, document_id: DocumentId, before_seq: i64) -> Result<u64, Self::Error>;
}

/// Document snapshot repository trait
#[async_trait]
pub trait DocumentSnapshotRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find snapshot by ID
    async fn find_by_id(&self, id: i64) -> Result<Option<DocumentSnapshot>, Self::Error>;

    /// Find snapshots by document ID
    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentSnapshot>, Self::Error>;

    /// Find latest snapshot for a document
    async fn find_latest_by_document_id(&self, document_id: DocumentId) -> Result<Option<DocumentSnapshot>, Self::Error>;

    /// Save snapshot
    async fn save(&self, snapshot: &DocumentSnapshot) -> Result<i64, Self::Error>;

    /// Delete snapshots by document ID
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}

/// Snapshot archive repository trait
#[async_trait]
pub trait SnapshotArchiveRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find archive by ID
    async fn find_by_id(&self, id: SnapshotArchiveId) -> Result<Option<DocumentSnapshotArchive>, Self::Error>;

    /// Find archives by document ID
    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentSnapshotArchive>, Self::Error>;

    /// Save archive
    async fn save(&self, archive: &DocumentSnapshotArchive) -> Result<(), Self::Error>;

    /// Delete archive
    async fn delete(&self, id: SnapshotArchiveId) -> Result<(), Self::Error>;

    /// Delete archives by document ID
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}

/// Tag repository trait
#[async_trait]
pub trait TagRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find tag by ID
    async fn find_by_id(&self, id: TagId) -> Result<Option<Tag>, Self::Error>;

    /// Find tags by workspace ID
    async fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Tag>, Self::Error>;

    /// Find tag by workspace and name
    async fn find_by_workspace_and_name(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
    ) -> Result<Option<Tag>, Self::Error>;

    /// Save tag (returns generated ID)
    async fn save(&self, tag: &Tag) -> Result<TagId, Self::Error>;

    /// Delete tag
    async fn delete(&self, id: TagId) -> Result<(), Self::Error>;
}

/// Document tag repository trait
#[async_trait]
pub trait DocumentTagRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find tags for a document
    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentTag>, Self::Error>;

    /// Find documents with a tag
    async fn find_by_tag_id(&self, tag_id: TagId) -> Result<Vec<DocumentTag>, Self::Error>;

    /// Save document tag
    async fn save(&self, document_tag: &DocumentTag) -> Result<(), Self::Error>;

    /// Delete document tag
    async fn delete(&self, document_id: DocumentId, tag_id: TagId) -> Result<(), Self::Error>;

    /// Delete all tags for a document
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}

/// Document link repository trait
#[async_trait]
pub trait DocumentLinkRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find link by ID
    async fn find_by_id(&self, id: DocumentLinkId) -> Result<Option<DocumentLink>, Self::Error>;

    /// Find outgoing links from a document
    async fn find_by_source_id(&self, source_id: DocumentId) -> Result<Vec<DocumentLink>, Self::Error>;

    /// Find incoming links (backlinks) to a document
    async fn find_by_target_id(&self, target_id: DocumentId) -> Result<Vec<DocumentLink>, Self::Error>;

    /// Save link
    async fn save(&self, link: &DocumentLink) -> Result<(), Self::Error>;

    /// Delete link
    async fn delete(&self, id: DocumentLinkId) -> Result<(), Self::Error>;

    /// Delete all links from a source document
    async fn delete_by_source_id(&self, source_id: DocumentId) -> Result<(), Self::Error>;

    /// Delete all links involving a document (as source or target)
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}
