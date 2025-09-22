use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::gitignore_port::GitignorePort;
use crate::application::ports::storage_port::StoragePort;

pub struct GetGitignorePatterns<'a, G, S>
where
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
{
    pub storage: &'a S,
    pub gitignore: &'a G,
}

impl<'a, G, S> GetGitignorePatterns<'a, G, S>
where
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
{
    pub async fn execute(&self, owner_id: uuid::Uuid) -> anyhow::Result<Vec<String>> {
        let dir = self.storage.user_repo_dir(owner_id);
        let patterns = self.gitignore.read_gitignore_patterns(&dir).await?;
        Ok(patterns)
    }
}

pub struct AddGitignorePatterns<'a, G, S, W>
where
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub storage: &'a S,
    pub gitignore: &'a G,
    pub workspace: &'a W,
}

impl<'a, G, S, W> AddGitignorePatterns<'a, G, S, W>
where
    G: GitignorePort + ?Sized,
    S: StoragePort + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        owner_id: uuid::Uuid,
        patterns: Vec<String>,
    ) -> anyhow::Result<usize> {
        self.workspace.ensure_repository(owner_id, "main").await?;
        let dir = self.storage.user_repo_dir(owner_id);
        let _ = self.gitignore.ensure_gitignore(&dir).await?;
        let added = self
            .gitignore
            .upsert_gitignore_patterns(&dir, &patterns)
            .await?;
        Ok(added)
    }
}

pub struct CheckPathIgnored<'a, G: GitignorePort + ?Sized, S: StoragePort + ?Sized> {
    pub gitignore: &'a G,
    pub storage: &'a S,
}

impl<'a, G: GitignorePort + ?Sized, S: StoragePort + ?Sized> CheckPathIgnored<'a, G, S> {
    pub async fn execute(&self, owner_id: uuid::Uuid, rel_path: &str) -> anyhow::Result<bool> {
        let dir = self.storage.user_repo_dir(owner_id);
        let patterns = self.gitignore.read_gitignore_patterns(&dir).await?;
        let p = rel_path.trim_start_matches('/');
        let mut is_ignored = false;
        for pat in &patterns {
            if pat.ends_with('/') {
                let prefix = pat.trim_end_matches('/');
                if p.starts_with(prefix) {
                    is_ignored = true;
                    break;
                }
            } else if pat == p {
                is_ignored = true;
                break;
            }
        }
        Ok(is_ignored)
    }
}
