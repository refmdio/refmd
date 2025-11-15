use std::sync::Arc;

use serde_json;
use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::application::ports::user_repository::UserRepository;

pub struct DeleteAccount<'a, UR, DR, PIR, PR, GR, GW, SJ, FR>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    GR: GitRepository + ?Sized,
    GW: GitWorkspacePort + ?Sized,
    SJ: StorageProjectionQueue + ?Sized,
    FR: FilesRepository + ?Sized,
{
    pub user_repo: &'a UR,
    pub document_repo: &'a DR,
    pub plugin_installations: &'a PIR,
    pub plugin_repo: &'a PR,
    pub plugin_assets: Arc<dyn PluginAssetStore>,
    pub git_repo: &'a GR,
    pub git_workspace: &'a GW,
    pub storage_jobs: &'a SJ,
    pub files_repo: &'a FR,
}

impl<'a, UR, DR, PIR, PR, GR, GW, SJ, FR>
    DeleteAccount<'a, UR, DR, PIR, PR, GR, GW, SJ, FR>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    GR: GitRepository + ?Sized,
    GW: GitWorkspacePort + ?Sized,
    SJ: StorageProjectionQueue + ?Sized,
    FR: FilesRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<()> {
        let doc_ids = self.document_repo.list_ids_for_user(user_id).await?;

        let installations = self.plugin_installations.list_for_user(user_id).await?;
        for inst in &installations {
            if let Err(err) = self
                .plugin_assets
                .remove_user_plugin_dir(&user_id, &inst.plugin_id)
                .await
            {
                tracing::warn!(user_id = %user_id, plugin_id = %inst.plugin_id, error = ?err, "failed to remove plugin assets for user");
            }
        }
        self.plugin_installations
            .remove_all_for_user(user_id)
            .await?;

        self.plugin_repo
            .delete_scoped_kv("user", &[user_id])
            .await?;
        self.plugin_repo
            .delete_scoped_records("user", &[user_id])
            .await?;

        if !doc_ids.is_empty() {
            self.plugin_repo.delete_scoped_kv("doc", &doc_ids).await?;
            self.plugin_repo
                .delete_scoped_records("doc", &doc_ids)
                .await?;
        }

        for doc_id in &doc_ids {
            if let Some(meta) = self
                .document_repo
                .get_meta_for_owner(*doc_id, user_id)
                .await?
            {
                let attachment_paths = if meta.doc_type != "folder" {
                    Some(
                        self.files_repo
                            .list_storage_paths_for_document(*doc_id)
                            .await?,
                    )
                } else {
                    None
                };
                let delete_metadata = StorageDeleteJobMetadata {
                    owner_id: user_id,
                    repo_path: Some(meta.desired_path.clone()),
                    doc_type: meta.doc_type.clone(),
                    attachment_paths,
                };
                let reason = serde_json::to_string(&StorageJobReason {
                    reason: "delete_account".to_string(),
                    metadata: Some(delete_metadata),
                })
                .ok();
                let reason_ref = reason.as_deref();
                let kind = match meta.doc_type.as_str() {
                    "folder" => StorageProjectionJobKind::DeleteFolder,
                    _ => StorageProjectionJobKind::DeleteDoc,
                };
                if let Err(err) = match kind {
                    StorageProjectionJobKind::DeleteFolder => {
                        self.storage_jobs
                            .enqueue_folder_job(*doc_id, kind, reason_ref)
                            .await
                    }
                    _ => {
                        self.storage_jobs
                            .enqueue_doc_job(*doc_id, kind, reason_ref)
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

        self.git_repo.delete_sync_logs(user_id).await?;
        if let Err(err) = self.git_workspace.remove_repository(user_id).await {
            tracing::warn!(user_id = %user_id, error = ?err, "failed to remove git workspace during account deletion");
        }
        let _ = self.git_repo.delete_config(user_id).await?;
        self.git_repo.delete_repository_state(user_id).await?;

        let deleted = self.user_repo.delete_user(user_id).await?;
        anyhow::ensure!(deleted, "user not found");

        Ok(())
    }
}
