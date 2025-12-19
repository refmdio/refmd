use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use crate::git::dtos::GitPullSessionDto;

#[async_trait]
pub trait GitPullSessionRepository: Send + Sync {
    async fn upsert(&self, session: GitPullSessionDto) -> PortResult<()>;
    async fn get(&self, workspace_id: Uuid, id: Uuid) -> PortResult<Option<GitPullSessionDto>>;
}
