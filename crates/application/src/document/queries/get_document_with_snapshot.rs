//! Fetch document snapshot and updates (pre-authorized)
//!
//! Returns the active collab snapshot + all updates for the snapshot.
//! Supports complete mode (all updates) and delta mode (updates after known state).
//! When `known_snapshot_id` is provided and differs from the active snapshot,
//! returns a proof chain for anti-rollback verification (regardless of mode).
//!
//! Used by the WebSocket handler where authorization has already been performed
//! at the HTTP upgrade step (pre-upgrade RBAC check per collaboration.md design).

use domain::document::{
    DocumentId, DocumentRepository, DocumentSnapshotId,
    DocumentSnapshotRepository, DocumentUpdateRepository,
};

use crate::dto::{DocumentSnapshotDto, DocumentUpdateDto, SnapshotProofDto};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Query mode (determines which updates to return)
#[derive(Debug, Clone)]
pub enum SnapshotQueryMode {
    /// Return snapshot + all updates
    Complete,
    /// Return updates after known per-device clocks only
    Delta {
        known_clocks: HashMap<String, i64>,
    },
}

/// Pre-authorized query for fetching document snapshot data (no user_id needed)
#[derive(Debug)]
pub struct FetchDocumentSnapshotQuery {
    pub document_id: DocumentId,
    pub mode: SnapshotQueryMode,
    /// Known snapshot ID for proof chain. When provided and differs from active
    /// snapshot, the server returns a proof chain for anti-rollback verification.
    pub known_snapshot_id: Option<DocumentSnapshotId>,
}

/// Fetch document snapshot result
#[derive(Debug)]
pub struct FetchDocumentSnapshotResult {
    pub snapshot: Option<DocumentSnapshotDto>,
    pub updates: Vec<DocumentUpdateDto>,
    /// Proof chain (non-empty when known_snapshot_id differs from active snapshot)
    pub proof_chain: Vec<SnapshotProofDto>,
}

/// Data-only error (no workspace access variants)
#[derive(Debug, Error)]
pub enum FetchDocumentSnapshotError<
    DR: std::error::Error,
    SR: std::error::Error,
    DUR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("snapshot repository error: {0}")]
    SnapshotRepository(SR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, SR: std::error::Error, DUR: std::error::Error]
    FetchDocumentSnapshotError<DR, SR, DUR>,
    not_found: [
        FetchDocumentSnapshotError::DocumentNotFound,
    ],
);

/// Pre-authorized document snapshot handler (data-only, no RBAC)
///
/// Used by the WebSocket handler where authorization has already been performed
/// at the HTTP upgrade step (pre-upgrade RBAC check per collaboration.md design).
pub struct FetchDocumentSnapshotHandler<DR: ?Sized, SR: ?Sized, DUR: ?Sized> {
    document_repo: Arc<DR>,
    snapshot_repo: Arc<SR>,
    update_repo: Arc<DUR>,
}

impl<DR: ?Sized, SR: ?Sized, DUR: ?Sized> FetchDocumentSnapshotHandler<DR, SR, DUR>
where
    DR: DocumentRepository,
    SR: DocumentSnapshotRepository,
    DUR: DocumentUpdateRepository,
{
    pub fn new(document_repo: Arc<DR>, snapshot_repo: Arc<SR>, update_repo: Arc<DUR>) -> Self {
        Self {
            document_repo,
            snapshot_repo,
            update_repo,
        }
    }

    pub async fn handle(
        &self,
        query: FetchDocumentSnapshotQuery,
    ) -> Result<
        FetchDocumentSnapshotResult,
        FetchDocumentSnapshotError<DR::Error, SR::Error, DUR::Error>,
    > {
        // Get active snapshot (may be None for newly created documents)
        let active = self.snapshot_repo
            .find_active_by_document_id(query.document_id)
            .await
            .map_err(FetchDocumentSnapshotError::SnapshotRepository)?;

        let Some((active_snapshot, snapshot_public_data)) = active else {
            // No active snapshot: verify document exists (not deleted between
            // pre-upgrade RBAC check and this query).
            let doc = self.document_repo
                .find_by_id(query.document_id)
                .await
                .map_err(FetchDocumentSnapshotError::DocumentRepository)?;
            if doc.is_none() {
                return Err(FetchDocumentSnapshotError::DocumentNotFound);
            }
            // Document exists but has no active snapshot: new document
            return Ok(FetchDocumentSnapshotResult {
                snapshot: None,
                updates: vec![],
                proof_chain: vec![],
            });
        };

        // Determine if this is a delta reconnect with the same snapshot
        let is_delta_same_snapshot = matches!(
            (&query.mode, query.known_snapshot_id),
            (SnapshotQueryMode::Delta { .. }, Some(known_id)) if known_id == active_snapshot.id
        );

        // Fetch updates based on mode
        let updates = match &query.mode {
            SnapshotQueryMode::Complete => {
                self.update_repo
                    .find_by_snapshot_id(active_snapshot.id, None)
                    .await
                    .map_err(FetchDocumentSnapshotError::UpdateRepository)?
            }
            SnapshotQueryMode::Delta { known_clocks } => {
                if is_delta_same_snapshot {
                    self.update_repo
                        .find_by_snapshot_id_after_clocks(active_snapshot.id, known_clocks)
                        .await
                        .map_err(FetchDocumentSnapshotError::UpdateRepository)?
                } else {
                    // Snapshot changed — return all updates for the new snapshot
                    self.update_repo
                        .find_by_snapshot_id(active_snapshot.id, None)
                        .await
                        .map_err(FetchDocumentSnapshotError::UpdateRepository)?
                }
            }
        };

        // Proof chain: returned when known_snapshot_id differs from active (mode-independent).
        // If the known snapshot is not in the ancestry chain, return empty proof chain.
        // The client is responsible for fail-closed anti-rollback verification when the
        // proof chain is missing but expected (collaboration.md: Cross-Snapshot verification).
        let proof_chain = match query.known_snapshot_id {
            Some(known_id) if known_id != active_snapshot.id => {
                self.snapshot_repo
                    .find_proof_chain(query.document_id, known_id, active_snapshot.id)
                    .await
                    .map_err(FetchDocumentSnapshotError::SnapshotRepository)?
            }
            _ => vec![],
        };

        // Delta same-snapshot: omit snapshot data (client already has it).
        // Client disambiguates null via connection mode + guard conditions
        // (collaboration.md: delta response snapshot:null disambiguation rule).
        let snapshot = if is_delta_same_snapshot {
            None
        } else {
            Some(DocumentSnapshotDto::from((active_snapshot, snapshot_public_data)))
        };

        Ok(FetchDocumentSnapshotResult {
            snapshot,
            updates: updates.into_iter().map(DocumentUpdateDto::from).collect(),
            proof_chain: proof_chain.into_iter().map(SnapshotProofDto::from).collect(),
        })
    }
}
