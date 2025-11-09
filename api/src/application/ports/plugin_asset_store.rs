use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PluginAssetPayload {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PluginAssetStoreScope<'a> {
    Global,
    User { owner_id: &'a Uuid },
}

#[async_trait]
pub trait PluginAssetStore: Send + Sync {
    async fn fetch_asset(
        &self,
        scope: PluginAssetStoreScope<'_>,
        plugin_id: &str,
        version: &str,
        relative_path: &str,
    ) -> anyhow::Result<PluginAssetPayload>;

    async fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()>;

    async fn list_latest_global_manifests(&self) -> anyhow::Result<Vec<(String, String, Value)>>;

    async fn load_user_manifest(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> anyhow::Result<Option<Value>>;
}
