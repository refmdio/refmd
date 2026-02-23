//! KEK/DEK rotation marking service
//!
//! Best-effort marks workspaces for KEK rotation and documents for DEK rotation.
//! Used after device revocation to ensure forward secrecy.

use domain::document::DocumentRepository;
use domain::encryption::DocumentEncryptedKeyRepository;
use domain::identity::UserId;
use domain::workspace::WorkspaceMemberRepository;
use std::sync::Arc;

use super::rotation_marking_service::{RotationMarkingError, RotationMarkingService};

/// Documents grouped by workspace that need DEK rotation
#[derive(Debug)]
pub struct WorkspaceDocumentsForRotation {
    pub workspace_id: uuid::Uuid,
    pub document_ids: Vec<uuid::Uuid>,
}

/// Report of failures during best-effort rotation marking
#[derive(Debug)]
pub struct RotationMarkingReport {
    pub failed_workspace_ids: Vec<uuid::Uuid>,
    pub failed_document_ids: Vec<uuid::Uuid>,
}

/// Result of rotation marking
#[derive(Debug)]
pub struct MarkRotationResult {
    pub workspaces_needing_kek_rotation: Vec<uuid::Uuid>,
    pub documents_needing_dek_rotation: Vec<WorkspaceDocumentsForRotation>,
    /// Total number of invitations revoked across all workspaces.
    pub revoked_invitation_count: i64,
    /// Non-fatal failures during rotation marking.
    /// `None` means all markers were saved successfully.
    pub rotation_marking_failures: Option<RotationMarkingReport>,
}

/// Service for marking workspaces/documents as needing key rotation.
///
/// Extracted from `RevokeDeviceHandler` so it can be reused by future
/// rotation features (e.g., scheduled rotation, member removal).
pub struct MarkRotationService<WMR: ?Sized, DocR: ?Sized, DKR: ?Sized> {
    workspace_member_repo: Arc<WMR>,
    document_repo: Arc<DocR>,
    document_key_repo: Arc<DKR>,
    rotation_marking_service: Arc<dyn RotationMarkingService>,
}

impl<WMR, DocR, DKR> MarkRotationService<WMR, DocR, DKR>
where
    WMR: WorkspaceMemberRepository + ?Sized,
    DocR: DocumentRepository + ?Sized,
    DKR: DocumentEncryptedKeyRepository + ?Sized,
{
    pub fn new(
        workspace_member_repo: Arc<WMR>,
        document_repo: Arc<DocR>,
        document_key_repo: Arc<DKR>,
        rotation_marking_service: Arc<dyn RotationMarkingService>,
    ) -> Self {
        Self {
            workspace_member_repo,
            document_repo,
            document_key_repo,
            rotation_marking_service,
        }
    }

    /// Mark all workspaces the user belongs to for KEK rotation,
    /// and all documents in those workspaces for DEK rotation.
    ///
    /// Failures are collected rather than aborting — a background job
    /// can detect missed markers.
    pub async fn mark_for_user(
        &self,
        user_id: UserId,
    ) -> Result<MarkRotationResult, MarkRotationError<WMR::Error>> {
        let mut workspace_ids_needing_rotation = Vec::new();
        let mut documents_needing_rotation = Vec::new();
        let mut failed_workspace_ids = Vec::new();
        let mut failed_document_ids = Vec::new();
        let mut revoked_invitation_count: i64 = 0;

        let members = self
            .workspace_member_repo
            .find_by_user_id(user_id)
            .await
            .map_err(MarkRotationError::WorkspaceMemberRepository)?;

        for member in members {
            match self
                .process_workspace_member(
                    member.workspace_id,
                    &mut failed_workspace_ids,
                    &mut failed_document_ids,
                    &mut revoked_invitation_count,
                )
                .await
            {
                Some((ws_id, doc_rotation)) => {
                    workspace_ids_needing_rotation.push(ws_id);
                    if let Some(rotation) = doc_rotation {
                        documents_needing_rotation.push(rotation);
                    }
                }
                None => continue,
            }
        }

        let rotation_marking_failures =
            if failed_workspace_ids.is_empty() && failed_document_ids.is_empty() {
                None
            } else {
                Some(RotationMarkingReport {
                    failed_workspace_ids,
                    failed_document_ids,
                })
            };

        Ok(MarkRotationResult {
            workspaces_needing_kek_rotation: workspace_ids_needing_rotation,
            documents_needing_dek_rotation: documents_needing_rotation,
            revoked_invitation_count,
            rotation_marking_failures,
        })
    }

    /// Mark a single workspace for KEK rotation and its documents for DEK rotation.
    ///
    /// Public entry point for callers that need to rotate a specific workspace
    /// (e.g., member removal). Returns `Ok(result)` on success, propagates errors.
    pub async fn mark_for_workspace(
        &self,
        workspace_id: domain::workspace::WorkspaceId,
    ) -> Result<MarkRotationResult, MarkRotationServiceError> {
        let mut failed_workspace_ids = Vec::new();
        let mut failed_document_ids = Vec::new();
        let mut revoked_invitation_count: i64 = 0;

        let result = self
            .process_workspace_member(
                workspace_id,
                &mut failed_workspace_ids,
                &mut failed_document_ids,
                &mut revoked_invitation_count,
            )
            .await;

        let mut workspaces_needing_kek_rotation = Vec::new();
        let mut documents_needing_dek_rotation = Vec::new();

        if let Some((ws_id, doc_rotation)) = result {
            workspaces_needing_kek_rotation.push(ws_id);
            if let Some(rotation) = doc_rotation {
                documents_needing_dek_rotation.push(rotation);
            }
        }

        let rotation_marking_failures =
            if failed_workspace_ids.is_empty() && failed_document_ids.is_empty() {
                None
            } else {
                Some(RotationMarkingReport {
                    failed_workspace_ids,
                    failed_document_ids,
                })
            };

        Ok(MarkRotationResult {
            workspaces_needing_kek_rotation,
            documents_needing_dek_rotation,
            revoked_invitation_count,
            rotation_marking_failures,
        })
    }

    /// Mark a single workspace for KEK rotation and its documents for DEK rotation.
    ///
    /// The workspace update and invitation revocation are performed atomically
    /// via [`RotationMarkingService`] to ensure both succeed or both rollback.
    ///
    /// Returns `Some((workspace_uuid, Option<docs_for_rotation>))` on success,
    /// `None` if the workspace was skipped due to errors.
    async fn process_workspace_member(
        &self,
        workspace_id: domain::workspace::WorkspaceId,
        failed_workspace_ids: &mut Vec<uuid::Uuid>,
        failed_document_ids: &mut Vec<uuid::Uuid>,
        revoked_invitation_count: &mut i64,
    ) -> Option<(uuid::Uuid, Option<WorkspaceDocumentsForRotation>)> {
        // Atomically set needs_kek_rotation = true and revoke all active
        // invitations. Both must succeed or both rollback to prevent stale-KEK
        // invitations from being accepted after a rotation is triggered.
        match self
            .rotation_marking_service
            .mark_rotation_and_revoke_invitations(workspace_id)
            .await
        {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(
                        workspace_id = %workspace_id,
                        count,
                        "revoked active invitations during KEK rotation marking"
                    );
                }
                *revoked_invitation_count += count;
            }
            Err(RotationMarkingError::WorkspaceNotFound) => return None,
            Err(e) => {
                tracing::error!(
                    "failed to mark workspace {} for KEK rotation and revoke invitations: {}",
                    workspace_id,
                    e
                );
                failed_workspace_ids.push(workspace_id.as_uuid());
                return None;
            }
        }

        let doc_rotation = self
            .process_workspace_documents(workspace_id, workspace_id.as_uuid(), failed_document_ids)
            .await;

        Some((workspace_id.as_uuid(), doc_rotation))
    }

    /// Mark all documents in a workspace for DEK rotation.
    async fn process_workspace_documents(
        &self,
        workspace_id: domain::workspace::WorkspaceId,
        workspace_uuid: uuid::Uuid,
        failed_document_ids: &mut Vec<uuid::Uuid>,
    ) -> Option<WorkspaceDocumentsForRotation> {
        let documents = match self.document_repo.find_by_workspace_id(workspace_id).await {
            Ok(docs) => docs,
            Err(e) => {
                tracing::error!(
                    "failed to fetch documents for workspace {} DEK rotation marking: {}",
                    workspace_id,
                    e
                );
                return None;
            }
        };

        let mut workspace_document_ids = Vec::new();
        for mut document in documents {
            document.mark_needs_dek_rotation();

            let max_version = match self.document_key_repo.find_by_document_id(document.id).await {
                Ok(keys) => keys.iter().map(|k| k.key_version.as_i32()).max().unwrap_or(0),
                Err(e) => {
                    tracing::error!(
                        "failed to fetch keys for document {} DEK rotation: {}",
                        document.id,
                        e
                    );
                    failed_document_ids.push(document.id.as_uuid());
                    continue;
                }
            };
            document.set_min_dek_version(max_version.saturating_add(1));

            if let Err(e) = self.document_repo.save(&document).await {
                tracing::error!(
                    "failed to mark document {} for DEK rotation: {}",
                    document.id,
                    e
                );
                failed_document_ids.push(document.id.as_uuid());
                continue;
            }
            workspace_document_ids.push(document.id.as_uuid());
        }

        if workspace_document_ids.is_empty() {
            None
        } else {
            Some(WorkspaceDocumentsForRotation {
                workspace_id: workspace_uuid,
                document_ids: workspace_document_ids,
            })
        }
    }
}

/// Error during single-workspace rotation marking (non-generic).
///
/// Used by `mark_for_workspace` which only delegates to dynamic-dispatch
/// services, so no generic repository error types are needed.
#[derive(Debug, thiserror::Error)]
pub enum MarkRotationServiceError {
    #[error("rotation marking failed: {0}")]
    RotationMarking(String),
}

/// Error during multi-workspace rotation marking (generic over member repo).
#[derive(Debug, thiserror::Error)]
pub enum MarkRotationError<WMR: std::error::Error> {
    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),
}
