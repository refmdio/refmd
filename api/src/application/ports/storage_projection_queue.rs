use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageProjectionJobKind {
    DocSync,
    FolderSync,
    DeleteDoc,
    DeleteFolder,
}

#[derive(Debug, Clone)]
pub struct StorageProjectionJob {
    pub id: i64,
    pub job_type: StorageProjectionJobKind,
    pub doc_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub reason: Option<String>,
    pub attempts: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeleteJobMetadata {
    pub owner_id: Uuid,
    pub repo_path: Option<String>,
    pub doc_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageJobReason<T> {
    pub reason: String,
    pub metadata: Option<T>,
}

#[async_trait]
pub trait StorageProjectionQueue: Send + Sync {
    async fn enqueue_doc_job(
        &self,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn enqueue_doc_job_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn enqueue_folder_job(
        &self,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn enqueue_folder_job_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn fetch_next_job(
        &self,
        lock_timeout_secs: i64,
    ) -> anyhow::Result<Option<StorageProjectionJob>>;

    async fn complete_job(&self, job_id: i64) -> anyhow::Result<()>;

    async fn fail_job(&self, job_id: i64, error: &str) -> anyhow::Result<()>;
}
