use tracing::warn;
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
        user_id: Uuid,
        req: GitSyncRequestDto,
    ) -> anyhow::Result<GitSyncResponseDto> {
        let cfg = self.repo.load_user_git_cfg(user_id).await?;
        let mut attempt_req = req.clone();
        let outcome = match self
            .workspace
            .sync(user_id, &attempt_req, cfg.as_ref())
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                if !attempt_req.force.unwrap_or(false) && needs_force_retry(&err) {
                    warn!(user_id = %user_id, "git_sync_retrying_with_force");
                    attempt_req.force = Some(true);
                    self.workspace
                        .sync(user_id, &attempt_req, cfg.as_ref())
                        .await?
                } else {
                    return Err(err);
                }
            }
        };

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

        let has_remote = cfg
            .as_ref()
            .map(|c| !c.repository_url.is_empty())
            .unwrap_or(false);
        // Success rule:
        // - If a remote is configured: success when push succeeded or there were no changes.
        // - If no remote: success when commit was created or there were no changes.
        let success = if has_remote {
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

fn needs_force_retry(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("remote repository state diverged")
        || msg.contains("repository latest commit mismatch")
        || msg.contains("remote repository already contains commit")
        || msg.contains("non-fast-forward")
        || msg.contains("non fast forward")
        || msg.contains("failed to push some refs")
        || msg.contains("rejected")
}
