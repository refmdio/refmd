use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PluginInstallation {
    pub user_id: Uuid,
    pub plugin_id: String,
    pub version: String,
    pub scope: String,
    pub origin_url: Option<String>,
    pub status: String,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PluginInstallationRepository: Send + Sync {
    async fn upsert(
        &self,
        user_id: Uuid,
        plugin_id: &str,
        version: &str,
        scope: &str,
        origin_url: Option<&str>,
        status: &str,
    ) -> anyhow::Result<()>;

    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<PluginInstallation>>;

    async fn remove(&self, user_id: Uuid, plugin_id: &str) -> anyhow::Result<bool>;
}
