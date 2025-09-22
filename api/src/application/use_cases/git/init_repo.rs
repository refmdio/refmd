use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::gitignore_port::GitignorePort;
use crate::application::ports::storage_port::StoragePort;
use uuid::Uuid;

pub struct InitRepo<'a, R, G, S, W>
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

impl<'a, R, G, S, W> InitRepo<'a, R, G, S, W>
where
    R: GitRepository + ?Sized,
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<()> {
        let default_branch = if let Some(row) = self.repo.get_config(user_id).await? {
            row.2
        } else {
            "main".to_string()
        };

        self.workspace
            .ensure_repository(user_id, &default_branch)
            .await?;

        let dir = self.storage.user_repo_dir(user_id);
        let _ = self.gitignore.ensure_gitignore(&dir).await?;
        Ok(())
    }
}

pub struct DeinitRepo<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> DeinitRepo<'a, W> {
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<()> {
        self.workspace.remove_repository(user_id).await
    }
}
