use uuid::Uuid;

use crate::application::dto::git::{GitSyncRequestDto, GitSyncResponseDto};
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
        workspace_id: Uuid,
        req: GitSyncRequestDto,
    ) -> anyhow::Result<GitSyncResponseDto> {
        let cfg = self.repo.load_user_git_cfg(workspace_id).await?;
        let attempt_req = req.clone();
        let outcome = self
            .workspace
            .sync(workspace_id, &attempt_req, cfg.as_ref())
            .await?;

        if let Some(cfg) = cfg.as_ref() {
            if !cfg.repository_url.is_empty() {
                if attempt_req.skip_push.unwrap_or(false) {
                    let _ = self
                        .repo
                        .log_sync_operation(
                            workspace_id,
                            "commit",
                            "success",
                            Some(&outcome.message),
                            outcome.commit_hash.as_deref(),
                        )
                        .await;
                } else {
                    // Treat "nothing to commit" as success even if no push occurred.
                    let status = if outcome.files_changed == 0 || outcome.pushed {
                        "success"
                    } else {
                        "error"
                    };
                    let _ = self
                        .repo
                        .log_sync_operation(
                            workspace_id,
                            "push",
                            status,
                            Some(&outcome.message),
                            outcome.commit_hash.as_deref(),
                        )
                        .await;
                }
            }
        }

        let has_remote = cfg
            .as_ref()
            .map(|c| !c.repository_url.is_empty())
            .unwrap_or(false);
        // Success rule:
        // - If a remote is configured: success when push succeeded or there were no changes.
        // - If no remote: success when commit was created or there were no changes.
        let skip_push = attempt_req.skip_push.unwrap_or(false);
        let success = if has_remote && !skip_push {
            outcome.files_changed == 0 || outcome.pushed
        } else {
            outcome.files_changed == 0 || outcome.commit_hash.is_some()
        };

        Ok(GitSyncResponseDto {
            success,
            message: outcome.message,
            commit_hash: outcome.commit_hash,
            files_changed: outcome.files_changed,
        })
    }
}
