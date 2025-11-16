use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GitRebuildJob {
    pub id: i64,
    pub user_id: Uuid,
    pub attempts: i32,
}

#[async_trait]
pub trait GitRebuildJobQueue: Send + Sync {
    async fn enqueue(&self, user_id: Uuid) -> anyhow::Result<()>;
    async fn fetch_next(&self, lock_timeout_secs: i64) -> anyhow::Result<Option<GitRebuildJob>>;
    async fn complete(&self, job_id: i64) -> anyhow::Result<()>;
    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()>;
}
