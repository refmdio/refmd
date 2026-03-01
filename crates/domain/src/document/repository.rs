//! Document repository traits

use async_trait::async_trait;
use std::collections::HashMap;

use super::document::Document;
use super::document_snapshot::{DocumentSnapshot, SnapshotProof};
use super::document_update::DocumentUpdate;
use super::value_objects::{DocumentId, DocumentSnapshotId, PublicData};
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

    /// Find document IDs in a workspace (lightweight, for scoped disconnect)
    async fn find_ids_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<DocumentId>, Self::Error>;

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

/// Document update repository trait (clock-based)
#[async_trait]
pub trait DocumentUpdateRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find updates belonging to a specific collab snapshot, optionally after a version
    async fn find_by_snapshot_id(
        &self,
        snapshot_id: DocumentSnapshotId,
        after_version: Option<i64>,
    ) -> Result<Vec<(DocumentUpdate, PublicData)>, Self::Error>;

    /// Save update with clock validation (Serializable transaction)
    /// Returns (id, clock, version) on success
    async fn save_with_clock(
        &self,
        update: &DocumentUpdate,
        snapshot_id: DocumentSnapshotId,
        public_data: PublicData,
    ) -> Result<(i64, i32, i64), Self::Error>;

    /// Check if an error represents a clock mismatch
    fn is_clock_mismatch(&self, err: &Self::Error) -> bool;

    /// Check if an error represents a snapshot mismatch (active snapshot changed)
    fn is_snapshot_mismatch(&self, err: &Self::Error) -> bool;

    /// Check if an error represents a key version too old (below min_dek_version)
    fn is_key_version_too_old(&self, err: &Self::Error) -> bool;

    /// Find updates by snapshot ID, filtering by per-device known clocks.
    /// Returns updates where the device is unknown to the caller, or clock > known_clock.
    async fn find_by_snapshot_id_after_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
        known_clocks: &std::collections::HashMap<String, i64>,
    ) -> Result<Vec<(DocumentUpdate, PublicData)>, Self::Error>;

    /// Delete updates by document ID
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}

/// Outcome of a snapshot save operation
#[derive(Debug, Clone, PartialEq)]
pub enum SnapshotSaveOutcome {
    /// Snapshot saved successfully
    Saved,
    /// CAS failed: active_snapshot_id did not match expected parent
    ParentMismatch,
    /// Clocks changed between validation and save (concurrent update)
    ClockMismatch,
    /// Key version is below min_dek_version (DEK rotation occurred concurrently)
    KeyVersionTooOld,
    /// Client-provided snapshot ID already exists (UUID collision or malicious replay)
    DuplicateId,
}

/// Collaboration snapshot repository trait
#[async_trait]
pub trait DocumentSnapshotRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find the active collab snapshot for a document
    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<(DocumentSnapshot, PublicData)>, Self::Error>;

    /// Find a snapshot by its ID
    async fn find_by_id(
        &self,
        id: DocumentSnapshotId,
    ) -> Result<Option<(DocumentSnapshot, PublicData)>, Self::Error>;

    /// Save a new snapshot and set it as active (Serializable transaction).
    /// Uses CAS: only sets active if current active_snapshot_id == expected_parent_id.
    /// When `expected_parent_id` is `None` (genesis), CAS checks `active_snapshot_id IS NULL`.
    /// Clock validation happens inside the transaction to prevent race conditions.
    async fn save(
        &self,
        snapshot: &DocumentSnapshot,
        expected_parent_id: Option<DocumentSnapshotId>,
        expected_parent_clocks: &HashMap<String, i64>,
        public_data: PublicData,
    ) -> Result<SnapshotSaveOutcome, Self::Error>;

    /// Find the proof chain from a given snapshot up to (and including) the target snapshot.
    /// Returns snapshots created strictly after `from_snapshot_id` and up to `up_to_snapshot_id`.
    async fn find_proof_chain(
        &self,
        document_id: DocumentId,
        from_snapshot_id: DocumentSnapshotId,
        up_to_snapshot_id: DocumentSnapshotId,
    ) -> Result<Vec<SnapshotProof>, Self::Error>;

    /// Get aggregate clocks for all updates in a snapshot
    async fn get_snapshot_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
    ) -> Result<HashMap<String, i64>, Self::Error>;

}
