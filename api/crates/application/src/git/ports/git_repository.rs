use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::git::auth::GitAuthType;
use domain::git::sync_log::{GitSyncOperation, GitSyncStatus};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GitConfigRecord {
    pub id: Uuid,
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: GitAuthType,
    pub auto_sync: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct GitLastSyncLog {
    pub created_at: Option<DateTime<Utc>>,
    pub status: Option<GitSyncStatus>,
    pub message: Option<String>,
    pub commit_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserGitCfg {
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: Option<GitAuthType>,
    pub auth_data: Option<Value>,
    pub auto_sync: bool,
}

#[async_trait]
pub trait GitRepository: Send + Sync {
    async fn get_config(&self, workspace_id: Uuid) -> anyhow::Result<Option<GitConfigRecord>>;
    async fn upsert_config(
        &self,
        workspace_id: Uuid,
        repository_url: &str,
        branch_name: Option<&str>,
        auth_type: GitAuthType,
        auth_data: &Value,
        auto_sync: Option<bool>,
    ) -> anyhow::Result<GitConfigRecord>;
    async fn delete_config(&self, workspace_id: Uuid) -> anyhow::Result<bool>;
    async fn load_user_git_cfg(&self, workspace_id: Uuid) -> anyhow::Result<Option<UserGitCfg>>;
    async fn get_last_sync_log(&self, workspace_id: Uuid)
    -> anyhow::Result<Option<GitLastSyncLog>>;
    async fn log_sync_operation(
        &self,
        workspace_id: Uuid,
        operation: GitSyncOperation,
        status: GitSyncStatus,
        message: Option<&str>,
        commit_hash: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn delete_sync_logs(&self, workspace_id: Uuid) -> anyhow::Result<()>;

    async fn delete_repository_state(&self, workspace_id: Uuid) -> anyhow::Result<()>;

    async fn list_auto_sync_workspaces(&self) -> anyhow::Result<Vec<Uuid>>;
}
