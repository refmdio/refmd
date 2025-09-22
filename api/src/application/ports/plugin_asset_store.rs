use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

#[async_trait]
pub trait PluginAssetStore: Send + Sync {
    fn global_root(&self) -> PathBuf;
    fn user_root(&self, user_id: &Uuid) -> PathBuf;
    fn latest_version_dir(&self, base: &Path) -> anyhow::Result<Option<PathBuf>>;
    fn user_plugin_manifest_path(&self, user_id: &Uuid, plugin_id: &str, version: &str) -> PathBuf;
    fn global_plugin_manifest_path(&self, plugin_id: &str, version: &str) -> PathBuf;
    fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()>;

    async fn list_latest_global_manifests(&self) -> anyhow::Result<Vec<(String, String, Value)>>;

    async fn load_user_manifest(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> anyhow::Result<Option<Value>>;
}
