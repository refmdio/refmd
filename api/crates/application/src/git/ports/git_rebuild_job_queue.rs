use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct GitRebuildJob {
    pub id: i64,
    pub workspace_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub attempts: i32,
    pub permission_snapshot: Vec<String>,
}

#[async_trait]
pub trait GitRebuildJobQueue: Send + Sync {
    async fn enqueue(
        &self,
        workspace_id: Uuid,
        actor_id: Option<Uuid>,
        permission_snapshot: &[String],
    ) -> PortResult<()>;
    async fn fetch_next(&self, lock_timeout_secs: i64) -> PortResult<Option<GitRebuildJob>>;
    async fn complete(&self, job_id: i64) -> PortResult<()>;
    async fn fail(&self, job_id: i64, error: &str) -> PortResult<()>;
}
