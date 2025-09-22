use uuid::Uuid;

use crate::application::ports::plugin_repository::{PluginRecord, PluginRepository};

pub struct ListPluginRecords<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> ListPluginRecords<'a, R> {
    pub async fn execute(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<PluginRecord>> {
        self.repo
            .list_records(plugin, scope, scope_id, kind, limit, offset)
            .await
    }
}

pub struct CreatePluginRecord<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> CreatePluginRecord<'a, R> {
    pub async fn execute(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<PluginRecord> {
        self.repo
            .insert_record(plugin, scope, scope_id, kind, data)
            .await
    }
}

pub struct UpdatePluginRecord<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> UpdatePluginRecord<'a, R> {
    pub async fn execute(
        &self,
        record_id: Uuid,
        patch: &serde_json::Value,
    ) -> anyhow::Result<Option<PluginRecord>> {
        self.repo.update_record_data(record_id, patch).await
    }
}

pub struct DeletePluginRecord<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> DeletePluginRecord<'a, R> {
    pub async fn execute(&self, record_id: Uuid) -> anyhow::Result<bool> {
        self.repo.delete_record(record_id).await
    }
}

pub struct GetPluginRecord<'a, R: PluginRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PluginRepository + ?Sized> GetPluginRecord<'a, R> {
    pub async fn execute(&self, record_id: Uuid) -> anyhow::Result<Option<PluginRecord>> {
        self.repo.get_record(record_id).await
    }
}
