use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct StorageReconcileJob {
    pub id: i64,
    pub workspace_id: Uuid,
    pub scope: String,
    pub attempts: i32,
}

#[async_trait]
pub trait StorageReconcileJobs: Send + Sync {
    async fn enqueue(&self, workspace_id: Uuid, scope: &str) -> PortResult<()>;
    async fn fetch_next(&self, lock_timeout_secs: i64) -> PortResult<Option<StorageReconcileJob>>;
    async fn complete(&self, job_id: i64) -> PortResult<()>;
    async fn fail(&self, job_id: i64, error: &str) -> PortResult<()>;
}
