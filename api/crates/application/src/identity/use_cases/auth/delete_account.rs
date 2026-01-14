use std::sync::Arc;

use serde_json;
use uuid::Uuid;

use crate::core::ports::storage::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::git::ports::git_repository::GitRepository;
use crate::identity::ports::user_repository::UserRepository;
use crate::plugins::ports::plugin_asset_store::PluginAssetStore;
use crate::plugins::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::plugins::ports::plugin_repository::PluginRepository;
use domain::access::permissions::PermissionSet;
use domain::documents::doc_type::DocumentType;
use domain::plugins::scope::{PluginRecordScope, PluginScope};

pub struct DeleteAccount<'a, UR, DR, PIR, PR, GR, SJ, FR>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    GR: GitRepository + ?Sized,
    SJ: StorageProjectionQueue + ?Sized,
    FR: FilesRepository + ?Sized,
{
    pub user_repo: &'a UR,
    pub document_repo: &'a DR,
    pub plugin_installations: &'a PIR,
    pub plugin_repo: &'a PR,
    pub plugin_assets: Arc<dyn PluginAssetStore>,
    pub git_repo: &'a GR,
    pub storage_jobs: &'a SJ,
    pub files_repo: &'a FR,
}

impl<'a, UR, DR, PIR, PR, GR, SJ, FR> DeleteAccount<'a, UR, DR, PIR, PR, GR, SJ, FR>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    GR: GitRepository + ?Sized,
    SJ: StorageProjectionQueue + ?Sized,
    FR: FilesRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<()> {
        let doc_ids = self.document_repo.list_ids_for_user(user_id).await?;

        let installations = self
            .plugin_installations
            .list_for_workspace(user_id)
            .await?;
        for inst in &installations {
            if let Err(err) = self
                .plugin_assets
                .remove_user_plugin_dir(&user_id, &inst.plugin_id)
                .await
            {
                tracing::warn!(
                    workspace_id = %user_id,
                    plugin_id = %inst.plugin_id,
                    error = ?err,
                    "failed to remove plugin assets for workspace"
                );
            }
        }
        self.plugin_installations
            .remove_all_for_workspace(user_id)
            .await?;

        self.plugin_repo
            .delete_scoped_kv(PluginScope::User, &[user_id])
            .await?;
        self.plugin_repo
            .delete_scoped_records(PluginRecordScope::User, &[user_id])
            .await?;

        if !doc_ids.is_empty() {
            self.plugin_repo
                .delete_scoped_kv(PluginScope::Doc, &doc_ids)
                .await?;
            self.plugin_repo
                .delete_scoped_records(PluginRecordScope::Doc, &doc_ids)
                .await?;
        }

        for doc_id in &doc_ids {
            if let Some(meta) = self
                .document_repo
                .get_meta_for_owner(*doc_id, user_id)
                .await?
            {
                let attachment_paths = if meta.doc_type != DocumentType::Folder {
                    Some(
                        self.files_repo
                            .list_storage_paths_for_document(*doc_id)
                            .await?,
                    )
                } else {
                    None
                };
                let delete_metadata = StorageDeleteJobMetadata {
                    workspace_id: meta.workspace_id,
                    repo_path: Some(meta.desired_path.as_str().to_string()),
                    doc_type: meta.doc_type,
                    attachment_paths,
                    permission_snapshot: PermissionSet::all().to_vec(),
                    actor_id: Some(user_id),
                };
                let reason = serde_json::to_string(&StorageJobReason {
                    reason: "delete_account".to_string(),
                    metadata: Some(delete_metadata),
                })
                .ok();
                let reason_ref = reason.as_deref();
                let kind = if meta.doc_type == DocumentType::Folder {
                    StorageProjectionJobKind::DeleteFolder
                } else {
                    StorageProjectionJobKind::DeleteDoc
                };
                if let Err(err) = match kind {
                    StorageProjectionJobKind::DeleteFolder => {
                        self.storage_jobs
                            .enqueue_folder_job(meta.workspace_id, *doc_id, kind, reason_ref)
                            .await
                    }
                    _ => {
                        self.storage_jobs
                            .enqueue_doc_job(meta.workspace_id, *doc_id, kind, reason_ref)
                            .await
                    }
                } {
                    tracing::warn!(
                        user_id = %user_id,
                        document_id = %doc_id,
                        error = ?err,
                        "storage_projection_enqueue_failed_during_account_delete"
                    );
                }
            }
        }

        // Delete git config (git repository data is stored client-side in IndexedDB for E2EE)
        let _ = self.git_repo.delete_config(user_id).await?;

        let deleted = self.user_repo.delete_user(user_id).await?;
        anyhow::ensure!(deleted, "user not found");

        Ok(())
    }
}
