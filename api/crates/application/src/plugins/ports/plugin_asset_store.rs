use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

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

#[derive(Debug, Clone)]
pub struct LatestGlobalManifest {
    pub plugin_id: String,
    pub version: String,
    pub manifest: Value,
}

#[async_trait]
pub trait PluginAssetStore: Send + Sync {
    async fn fetch_asset(
        &self,
        scope: PluginAssetStoreScope<'_>,
        plugin_id: &str,
        version: &str,
        relative_path: &str,
    ) -> PortResult<PluginAssetPayload>;

    async fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> PortResult<()>;

    async fn list_latest_global_manifests(&self) -> PortResult<Vec<LatestGlobalManifest>>;

    async fn load_user_manifest(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> PortResult<Option<Value>>;
}
