use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::git::auth::GitAuthType;
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct GitConfigRecord {
    pub id: Uuid,
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: GitAuthType,
    pub auto_sync: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Raw auth_data from database (E2EE encrypted data is stored as-is)
    pub auth_data: Option<Value>,
}

#[async_trait]
pub trait GitRepository: Send + Sync {
    async fn get_config(&self, workspace_id: Uuid) -> PortResult<Option<GitConfigRecord>>;
    async fn upsert_config(
        &self,
        workspace_id: Uuid,
        repository_url: &str,
        branch_name: Option<&str>,
        auth_type: GitAuthType,
        auth_data: &Value,
        auto_sync: Option<bool>,
    ) -> PortResult<GitConfigRecord>;
    async fn delete_config(&self, workspace_id: Uuid) -> PortResult<bool>;
}
