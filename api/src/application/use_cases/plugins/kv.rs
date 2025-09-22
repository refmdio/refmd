use uuid::Uuid;

use crate::application::ports::plugin_repository::PluginRepository;

pub struct GetPluginKv<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> GetPluginKv<'a, R> {
    pub async fn execute(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        self.repo.kv_get(plugin, scope, scope_id, key).await
    }
}

pub struct PutPluginKv<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> PutPluginKv<'a, R> {
    pub async fn execute(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
        value: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.repo.kv_set(plugin, scope, scope_id, key, value).await
    }
}
