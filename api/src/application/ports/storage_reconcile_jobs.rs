use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StorageReconcileJob {
    pub id: i64,
    pub workspace_id: Uuid,
    pub scope: String,
    pub attempts: i32,
}

#[async_trait]
pub trait StorageReconcileJobs: Send + Sync {
    async fn enqueue(&self, workspace_id: Uuid, scope: &str) -> anyhow::Result<()>;
    async fn fetch_next(
        &self,
        lock_timeout_secs: i64,
    ) -> anyhow::Result<Option<StorageReconcileJob>>;
    async fn complete(&self, job_id: i64) -> anyhow::Result<()>;
    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()>;
}
