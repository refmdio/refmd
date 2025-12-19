use crate::git::dtos::{GitStatusDto, GitWorkspaceStatus};
use crate::git::ports::git_repository::GitRepository;
use crate::git::ports::git_workspace::GitWorkspacePort;
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
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<GitStatusDto> {
        let cfg_row = self.repo.get_config(workspace_id).await?;
        let (repository_url, auto_sync) = cfg_row
            .map(|cfg| (cfg.repository_url, cfg.auto_sync))
            .unwrap_or((String::new(), false));

        let GitWorkspaceStatus {
            repository_initialized,
            current_branch,
            uncommitted_changes,
            untracked_files,
        } = self.workspace.status(workspace_id).await?;

        let last = self.repo.get_last_sync_log(workspace_id).await?;
        let (last_sync, last_sync_status, last_sync_message, last_sync_commit_hash) = match last {
            Some(log) => (
                log.created_at,
                log.status.map(|s| s.as_str().to_string()),
                log.message,
                log.commit_hash,
            ),
            None => (None, None, None, None),
        };

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
