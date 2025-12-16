use async_trait::async_trait;
use uuid::Uuid;

use crate::contracts::diff::TextDiffResult;
use crate::contracts::git::{
    GitChangeItem, GitCommitInfo, GitImportOutcome, GitPullRequestDto, GitPullResultDto,
    GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::ports::git_repository::UserGitCfg;

#[async_trait]
pub trait GitWorkspacePort: Send + Sync {
    async fn ensure_repository(
        &self,
        workspace_id: Uuid,
        default_branch: &str,
    ) -> anyhow::Result<()>;
    async fn remove_repository(&self, workspace_id: Uuid) -> anyhow::Result<()>;
    async fn status(&self, workspace_id: Uuid) -> anyhow::Result<GitWorkspaceStatus>;
    async fn list_changes(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>>;
    async fn working_diff(&self, workspace_id: Uuid) -> anyhow::Result<Vec<TextDiffResult>>;
    async fn commit_diff(
        &self,
        workspace_id: Uuid,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<TextDiffResult>>;
    async fn history(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>>;
    async fn sync(
        &self,
        workspace_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome>;
    async fn import_repository(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitImportOutcome>;
    async fn pull(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitPullResultDto>;
    async fn head_commit(&self, workspace_id: Uuid) -> anyhow::Result<Option<Vec<u8>>>;
    async fn remote_head(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn has_pending_changes(&self, workspace_id: Uuid) -> anyhow::Result<bool>;
    async fn drift_since_commit(
        &self,
        workspace_id: Uuid,
        base_commit: &[u8],
    ) -> anyhow::Result<bool>;

    async fn check_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitRemoteCheckDto>;
}
