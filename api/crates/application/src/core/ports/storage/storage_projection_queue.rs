use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::documents::doc_type::DocumentType;

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
    pub workspace_id: Uuid,
    pub job_type: StorageProjectionJobKind,
    pub doc_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub reason: Option<String>,
    pub attempts: i32,
    pub locked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeleteJobMetadata {
    pub workspace_id: Uuid,
    pub repo_path: Option<String>,
    pub doc_type: DocumentType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_paths: Option<Vec<String>>,
    #[serde(default)]
    pub permission_snapshot: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceJobMetadata {
    pub workspace_id: Uuid,
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
        workspace_id: Uuid,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()>;

    async fn enqueue_folder_job(
        &self,
        workspace_id: Uuid,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()>;

    async fn fetch_next_job(
        &self,
        lock_timeout_secs: i64,
    ) -> PortResult<Option<StorageProjectionJob>>;

    async fn complete_job(&self, job_id: i64, locked_at: DateTime<Utc>) -> PortResult<()>;

    async fn fail_job(&self, job_id: i64, locked_at: DateTime<Utc>, error: &str) -> PortResult<()>;
}

#[async_trait]
pub trait StorageProjectionQueueTx: Send {
    async fn enqueue_doc_job(
        &mut self,
        workspace_id: Uuid,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()>;

    async fn enqueue_folder_job(
        &mut self,
        workspace_id: Uuid,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()>;
}
