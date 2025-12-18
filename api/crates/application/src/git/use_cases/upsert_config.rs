use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::git::dtos::{GitConfigDto, UpsertGitConfigInput};
use crate::git::ports::git_repository::GitRepository;
use crate::git::ports::git_workspace::GitWorkspacePort;
use crate::git::ports::gitignore_port::GitignorePort;
use domain::git::auth::GitAuthType;
use uuid::Uuid;

pub struct UpsertGitConfig<'a, R, G, S, W>
where
    R: GitRepository + ?Sized,
    G: GitignorePort + ?Sized,
    S: StorageResolverPort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub repo: &'a R,
    pub storage: &'a S,
    pub gitignore: &'a G,
    pub workspace: &'a W,
}

impl<'a, R, G, S, W> UpsertGitConfig<'a, R, G, S, W>
where
    R: GitRepository + ?Sized,
    G: GitignorePort + ?Sized,
    S: StorageResolverPort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        req: &UpsertGitConfigInput,
    ) -> anyhow::Result<GitConfigDto> {
        let auth_type =
            GitAuthType::from_str(&req.auth_type).ok_or_else(|| anyhow::anyhow!("bad_request"))?;
        if !auth_type.validate_repository_url(&req.repository_url) {
            anyhow::bail!("bad_request");
        }
        let record = self
            .repo
            .upsert_config(
                workspace_id,
                &req.repository_url,
                req.branch_name.as_deref(),
                auth_type,
                &req.auth_data,
                req.auto_sync,
            )
            .await?;
        self.workspace
            .ensure_repository(workspace_id, &record.branch_name)
            .await?;
        let dir = self.storage.user_repo_dir(workspace_id);
        let _ = self.gitignore.ensure_gitignore(&dir).await?;
        Ok(GitConfigDto {
            id: record.id,
            repository_url: record.repository_url,
            branch_name: record.branch_name,
            auth_type: record.auth_type.as_str().to_string(),
            auto_sync: record.auto_sync,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}
