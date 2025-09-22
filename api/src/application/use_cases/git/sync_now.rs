use uuid::Uuid;

use crate::application::dto::git::{GitSyncOutcome, GitSyncRequestDto, GitSyncResponseDto};
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;

pub struct SyncNow<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub workspace: &'a W,
    pub repo: &'a R,
}

impl<'a, R, W> SyncNow<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        req: GitSyncRequestDto,
    ) -> anyhow::Result<GitSyncResponseDto> {
        let cfg = self.repo.load_user_git_cfg(user_id).await?;
        let outcome: GitSyncOutcome = self.workspace.sync(user_id, &req, cfg.as_ref()).await?;

        if let Some(cfg) = cfg.as_ref() {
            if !cfg.repository_url.is_empty() {
                let status = if outcome.pushed { "success" } else { "error" };
                let _ = self
                    .repo
                    .log_sync_operation(
                        user_id,
                        "push",
                        status,
                        Some(&outcome.message),
                        outcome.commit_hash.as_deref(),
                    )
                    .await;
            }
        }

        let success = outcome.files_changed == 0 || outcome.pushed || outcome.commit_hash.is_some();

        Ok(GitSyncResponseDto {
            success,
            message: outcome.message,
            commit_hash: outcome.commit_hash,
            files_changed: outcome.files_changed,
        })
    }
}
