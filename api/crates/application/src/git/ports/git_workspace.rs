use async_trait::async_trait;
use uuid::Uuid;

use crate::core::dtos::TextDiffResult;
use crate::core::ports::errors::PortResult;
use crate::git::dtos::{
    GitChangeItem, GitCommitInfo, GitImportOutcome, GitPullRequestDto, GitPullResultDto,
    GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::git::ports::git_repository::UserGitCfg;

#[async_trait]
pub trait GitWorkspacePort: Send + Sync {
    async fn ensure_repository(&self, workspace_id: Uuid, default_branch: &str) -> PortResult<()>;
    async fn remove_repository(&self, workspace_id: Uuid) -> PortResult<()>;
    async fn status(&self, workspace_id: Uuid) -> PortResult<GitWorkspaceStatus>;
    async fn list_changes(&self, workspace_id: Uuid) -> PortResult<Vec<GitChangeItem>>;
    async fn working_diff(&self, workspace_id: Uuid) -> PortResult<Vec<TextDiffResult>>;
    async fn commit_diff(
        &self,
        workspace_id: Uuid,
        from: &str,
        to: &str,
    ) -> PortResult<Vec<TextDiffResult>>;
    async fn history(&self, workspace_id: Uuid) -> PortResult<Vec<GitCommitInfo>>;
    async fn sync(
        &self,
        workspace_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> PortResult<GitSyncOutcome>;
    async fn import_repository(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<GitImportOutcome>;
    async fn pull(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> PortResult<GitPullResultDto>;
    async fn head_commit(&self, workspace_id: Uuid) -> PortResult<Option<Vec<u8>>>;
    async fn remote_head(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<Option<Vec<u8>>>;
    async fn has_pending_changes(&self, workspace_id: Uuid) -> PortResult<bool>;
    async fn drift_since_commit(&self, workspace_id: Uuid, base_commit: &[u8]) -> PortResult<bool>;

    async fn check_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<GitRemoteCheckDto>;
}
