use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::plugins::scope::{PluginInstallationStatus, PluginScope};

#[derive(Debug, Clone)]
pub struct PluginInstallation {
    pub workspace_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub scope: PluginScope,
    pub origin_url: Option<String>,
    pub status: PluginInstallationStatus,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PluginInstallationRepository: Send + Sync {
    async fn upsert(
        &self,
        workspace_id: Uuid,
        plugin_id: &str,
        version: &str,
        scope: PluginScope,
        origin_url: Option<&str>,
        status: PluginInstallationStatus,
    ) -> PortResult<()>;

    async fn list_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<PluginInstallation>>;

    async fn list_all(&self) -> PortResult<Vec<PluginInstallation>>;

    async fn remove(&self, workspace_id: Uuid, plugin_id: &str) -> PortResult<bool>;

    async fn remove_all_for_workspace(&self, workspace_id: Uuid) -> PortResult<()>;
}
