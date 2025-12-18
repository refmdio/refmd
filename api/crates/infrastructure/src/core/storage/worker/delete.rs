use std::path::PathBuf;

use tracing::{info, warn};
use uuid::Uuid;

use application::core::ports::storage::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason,
};
use application::workspaces::services::permission_snapshot::permission_set_from_snapshot;
use domain::documents::doc_type::DocumentType;
use domain::workspaces::permissions::{
    PERM_DOC_DELETE, PERM_FILE_DELETE, PERM_FOLDER_DELETE, PermissionSet,
};

use super::StorageProjectionWorker;

pub(super) fn parse_delete_job_metadata(
    reason: Option<&String>,
) -> Option<StorageDeleteJobMetadata> {
    reason.and_then(|raw| {
        serde_json::from_str::<StorageJobReason<StorageDeleteJobMetadata>>(raw)
            .ok()
            .and_then(|wrapper| wrapper.metadata)
    })
}

fn workspace_repo_relative(workspace_id: Uuid, repo_path: &str) -> String {
    let mut full = PathBuf::from(workspace_id.to_string());
    full.push(repo_path.trim_start_matches('/'));
    normalize_relative_path(full)
}

fn normalize_relative_path(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}

const FALLBACK_DELETE_PERMISSIONS: &[&str] =
    &[PERM_DOC_DELETE, PERM_FOLDER_DELETE, PERM_FILE_DELETE];

impl StorageProjectionWorker {
    pub(super) async fn handle_delete_doc(
        &self,
        doc_id: Uuid,
        metadata: Option<&StorageDeleteJobMetadata>,
    ) -> anyhow::Result<()> {
        self.storage.delete_doc_physical(doc_id).await?;
        if let Some(meta) = metadata {
            self.delete_doc_by_metadata(meta).await?;
        }
        Ok(())
    }

    pub(super) async fn handle_delete_folder(
        &self,
        folder_id: Uuid,
        metadata: Option<&StorageDeleteJobMetadata>,
    ) -> anyhow::Result<()> {
        self.storage.delete_folder_physical(folder_id).await?;
        if let Some(meta) = metadata {
            self.delete_folder_by_metadata(meta).await?;
        }
        Ok(())
    }

    pub(super) async fn delete_doc_by_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<()> {
        let permissions = self.permission_set_from_metadata(metadata).await?;
        if metadata.doc_type == DocumentType::Folder {
            if !permissions.allows(PERM_FOLDER_DELETE) {
                warn!(
                    workspace_id = %metadata.workspace_id,
                    "storage_projection_folder_delete_permission_denied"
                );
            }
            return Ok(());
        }
        if !permissions.allows(PERM_DOC_DELETE) {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_doc_delete_permission_denied"
            );
            return Ok(());
        }
        let Some(repo_path) = metadata.repo_path.as_deref() else {
            return Ok(());
        };
        let doc_relative = workspace_repo_relative(metadata.workspace_id, repo_path);
        self.storage.delete_relative_path(&doc_relative).await?;
        if let Some(paths) = metadata.attachment_paths.as_ref() {
            let can_delete_attachments = permissions.allows(PERM_FILE_DELETE);
            for rel in paths {
                if !can_delete_attachments {
                    warn!(
                        workspace_id = %metadata.workspace_id,
                        attachment_path = rel.as_str(),
                        "storage_projection_attachment_delete_permission_denied"
                    );
                    break;
                }
                if let Err(err) = self.storage.delete_relative_path(rel).await {
                    warn!(
                        workspace_id = %metadata.workspace_id,
                        attachment_path = rel.as_str(),
                        error = ?err,
                        "storage_attachment_delete_failed"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) async fn delete_folder_by_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<()> {
        let Some(repo_path) = metadata.repo_path.as_deref() else {
            return Ok(());
        };
        let permissions = self.permission_set_from_metadata(metadata).await?;
        if !permissions.allows(PERM_FOLDER_DELETE) {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_folder_delete_permission_denied"
            );
            return Ok(());
        }
        let folder_relative = workspace_repo_relative(metadata.workspace_id, repo_path);
        self.storage.delete_relative_path(&folder_relative).await?;
        Ok(())
    }

    pub(super) async fn permission_set_from_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<PermissionSet> {
        let set = permission_set_from_snapshot(&metadata.permission_snapshot);
        if !set.is_empty() {
            return Ok(set);
        }
        if let Some(actor_id) = metadata.actor_id {
            match self
                .permission_resolver
                .load_permission_set(metadata.workspace_id, actor_id)
                .await
            {
                Ok(Some(resolved)) => {
                    info!(
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_permissions_rehydrated"
                    );
                    return Ok(resolved);
                }
                Ok(None) => {
                    warn!(
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_actor_missing_for_permissions"
                    );
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_permission_resolve_failed"
                    );
                }
            }
        } else {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_permission_snapshot_missing_no_actor"
            );
        }
        Ok(PermissionSet::from_slice(FALLBACK_DELETE_PERMISSIONS))
    }
}
