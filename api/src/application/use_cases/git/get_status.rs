use crate::application::dto::git::{GitStatusDto, GitWorkspaceStatus};
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetGitStatus<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub repo: &'a R,
    pub workspace: &'a W,
}

impl<'a, R, W> GetGitStatus<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<GitStatusDto> {
        let cfg_row = self.repo.get_config(user_id).await?;
        let (repository_url, auto_sync) =
            if let Some((_id, url, _branch, _auth_type, auto_sync, _c, _u)) = cfg_row {
                (url, auto_sync)
            } else {
                (String::new(), false)
            };

        let GitWorkspaceStatus {
            repository_initialized,
            current_branch,
            uncommitted_changes,
            untracked_files,
        } = self.workspace.status(user_id).await?;

        let (last_sync, last_sync_status, last_sync_message, last_sync_commit_hash) = self
            .repo
            .get_last_sync_log(user_id)
            .await?
            .unwrap_or((None, None, None, None));

        Ok(GitStatusDto {
            repository_initialized,
            has_remote: !repository_url.is_empty(),
            current_branch,
            uncommitted_changes,
            untracked_files,
            last_sync,
            last_sync_status,
            last_sync_message,
            last_sync_commit_hash,
            sync_enabled: auto_sync,
        })
    }
}
