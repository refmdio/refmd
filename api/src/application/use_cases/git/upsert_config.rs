use crate::application::dto::git::{GitConfigDto, UpsertGitConfigInput};
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::gitignore_port::GitignorePort;
use crate::application::ports::storage_port::StoragePort;
use uuid::Uuid;

pub struct UpsertGitConfig<'a, R, G, S, W>
where
    R: GitRepository + ?Sized,
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
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
    S: StoragePort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        req: &UpsertGitConfigInput,
    ) -> anyhow::Result<GitConfigDto> {
        if req.auth_type != "token" && req.auth_type != "ssh" {
            anyhow::bail!("bad_request");
        }
        if req.auth_type == "token" && !req.repository_url.starts_with("https://") {
            anyhow::bail!("bad_request");
        }
        let (id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at) = self
            .repo
            .upsert_config(
                user_id,
                &req.repository_url,
                req.branch_name.as_deref(),
                &req.auth_type,
                &req.auth_data,
                req.auto_sync,
            )
            .await?;
        self.workspace
            .ensure_repository(user_id, &branch_name)
            .await?;
        let dir = self.storage.user_repo_dir(user_id);
        let _ = self.gitignore.ensure_gitignore(&dir).await?;
        Ok(GitConfigDto {
            id,
            repository_url,
            branch_name,
            auth_type,
            auto_sync,
            created_at,
            updated_at,
        })
    }
}
