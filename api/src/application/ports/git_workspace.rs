use async_trait::async_trait;
use uuid::Uuid;

use crate::application::dto::git::{
    DiffResult, GitChangeItem, GitCommitInfo, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::application::ports::git_repository::UserGitCfg;

#[async_trait]
pub trait GitWorkspacePort: Send + Sync {
    async fn ensure_repository(&self, user_id: Uuid, default_branch: &str) -> anyhow::Result<()>;
    async fn remove_repository(&self, user_id: Uuid) -> anyhow::Result<()>;
    async fn status(&self, user_id: Uuid) -> anyhow::Result<GitWorkspaceStatus>;
    async fn list_changes(&self, user_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>>;
    async fn working_diff(&self, user_id: Uuid) -> anyhow::Result<Vec<DiffResult>>;
    async fn commit_diff(
        &self,
        user_id: Uuid,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<DiffResult>>;
    async fn history(&self, user_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>>;
    async fn sync(
        &self,
        user_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome>;
}
