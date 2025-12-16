use async_trait::async_trait;
use uuid::Uuid;

use crate::contracts::git::GitPullSessionDto;

#[async_trait]
pub trait GitPullSessionRepository: Send + Sync {
    async fn upsert(&self, session: GitPullSessionDto) -> anyhow::Result<()>;
    async fn get(&self, workspace_id: Uuid, id: Uuid) -> anyhow::Result<Option<GitPullSessionDto>>;
}
