use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::user_repository::UserRepository;

pub struct DeleteAccount<'a, UR, DR, SP, PIR, PR, PAS, GR, GW>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    SP: StoragePort + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    PAS: PluginAssetStore + ?Sized,
    GR: GitRepository + ?Sized,
    GW: GitWorkspacePort + ?Sized,
{
    pub user_repo: &'a UR,
    pub document_repo: &'a DR,
    pub storage: &'a SP,
    pub plugin_installations: &'a PIR,
    pub plugin_repo: &'a PR,
    pub plugin_assets: &'a PAS,
    pub git_repo: &'a GR,
    pub git_workspace: &'a GW,
}

impl<'a, UR, DR, SP, PIR, PR, PAS, GR, GW> DeleteAccount<'a, UR, DR, SP, PIR, PR, PAS, GR, GW>
where
    UR: UserRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    SP: StoragePort + ?Sized,
    PIR: PluginInstallationRepository + ?Sized,
    PR: PluginRepository + ?Sized,
    PAS: PluginAssetStore + ?Sized,
    GR: GitRepository + ?Sized,
    GW: GitWorkspacePort + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<()> {
        let doc_ids = self.document_repo.list_ids_for_user(user_id).await?;

        let installations = self.plugin_installations.list_for_user(user_id).await?;
        for inst in &installations {
            if let Err(err) = self
                .plugin_assets
                .remove_user_plugin_dir(&user_id, &inst.plugin_id)
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
            if let Err(err) = self.storage.delete_doc_physical(*doc_id).await {
                tracing::warn!(user_id = %user_id, document_id = %doc_id, error = ?err, "failed to remove document artifacts during account deletion");
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
