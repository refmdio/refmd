//! KEK/DEK rotation marking service
//!
//! Best-effort marks workspaces for KEK rotation and documents for DEK rotation.
//! Used after device revocation to ensure forward secrecy.

use domain::document::DocumentRepository;
use domain::encryption::DocumentEncryptedKeyRepository;
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspaceRepository};
use std::sync::Arc;

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
    /// Non-fatal failures during rotation marking.
    /// `None` means all markers were saved successfully.
    pub rotation_marking_failures: Option<RotationMarkingReport>,
}

/// Service for marking workspaces/documents as needing key rotation.
///
/// Extracted from `RevokeDeviceHandler` so it can be reused by future
/// rotation features (e.g., scheduled rotation, member removal).
pub struct MarkRotationService<WMR: ?Sized, WR: ?Sized, DocR: ?Sized, DKR: ?Sized> {
    workspace_member_repo: Arc<WMR>,
    workspace_repo: Arc<WR>,
    document_repo: Arc<DocR>,
    document_key_repo: Arc<DKR>,
}

impl<WMR, WR, DocR, DKR> MarkRotationService<WMR, WR, DocR, DKR>
where
    WMR: WorkspaceMemberRepository + ?Sized,
    WR: WorkspaceRepository + ?Sized,
    DocR: DocumentRepository + ?Sized,
    DKR: DocumentEncryptedKeyRepository + ?Sized,
{
    pub fn new(
        workspace_member_repo: Arc<WMR>,
        workspace_repo: Arc<WR>,
        document_repo: Arc<DocR>,
        document_key_repo: Arc<DKR>,
    ) -> Self {
        Self {
            workspace_member_repo,
            workspace_repo,
            document_repo,
            document_key_repo,
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
            rotation_marking_failures,
        })
    }

    /// Mark a single workspace for KEK rotation and its documents for DEK rotation.
    ///
    /// Returns `Some((workspace_uuid, Option<docs_for_rotation>))` on success,
    /// `None` if the workspace was skipped due to errors.
    async fn process_workspace_member(
        &self,
        workspace_id: domain::workspace::WorkspaceId,
        failed_workspace_ids: &mut Vec<uuid::Uuid>,
        failed_document_ids: &mut Vec<uuid::Uuid>,
    ) -> Option<(uuid::Uuid, Option<WorkspaceDocumentsForRotation>)> {
        let mut workspace = match self.workspace_repo.find_by_id(workspace_id).await {
            Ok(Some(w)) => w,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(
                    "failed to fetch workspace {} for KEK rotation marking: {}",
                    workspace_id,
                    e
                );
                failed_workspace_ids.push(workspace_id.as_uuid());
                return None;
            }
        };

        workspace.mark_needs_kek_rotation();
        if let Err(e) = self.workspace_repo.save(&workspace).await {
            tracing::error!(
                "failed to mark workspace {} for KEK rotation: {}",
                workspace.id,
                e
            );
            failed_workspace_ids.push(workspace.id.as_uuid());
            return None;
        }

        let doc_rotation = self
            .process_workspace_documents(workspace_id, workspace.id.as_uuid(), failed_document_ids)
            .await;

        Some((workspace.id.as_uuid(), doc_rotation))
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

/// Error during rotation marking
#[derive(Debug, thiserror::Error)]
pub enum MarkRotationError<WMR: std::error::Error> {
    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),
}
