use anyhow::anyhow;
use uuid::Uuid;

use crate::application::dto::git::{GitPullRequestDto, GitPullResultDto};
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;

pub struct PullRepository<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub workspace: &'a W,
    pub repo: &'a R,
}

impl<'a, R, W> PullRepository<'a, R, W>
where
    R: GitRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        req: GitPullRequestDto,
    ) -> anyhow::Result<GitPullResultDto> {
        let cfg = self.repo.load_user_git_cfg(workspace_id).await?;
        let cfg = cfg.ok_or_else(|| anyhow!("git_not_configured"))?;
        self.workspace.pull(workspace_id, &req, &cfg).await
    }
}
