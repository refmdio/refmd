use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::plugins::ports::plugin_repository::{PluginRecord, PluginRepository};
use crate::plugins::use_cases::kv::{GetPluginKv, PutPluginKv};
use crate::plugins::use_cases::records::{
    CreatePluginRecord, DeletePluginRecord, GetPluginRecord, ListPluginRecords, UpdatePluginRecord,
};
use async_trait::async_trait;
use domain::plugins::scope::{PluginRecordScope, PluginScope};

pub struct PluginDataService {
    repo: Arc<dyn PluginRepository>,
}

#[async_trait]
pub trait PluginDataServiceFacade: Send + Sync {
    async fn list_records(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PluginRecord>, ServiceError>;

    async fn create_record(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        data: &serde_json::Value,
    ) -> Result<PluginRecord, ServiceError>;

    async fn get_record(&self, record_id: Uuid) -> Result<Option<PluginRecord>, ServiceError>;

    async fn update_record(
        &self,
        record_id: Uuid,
        patch: &serde_json::Value,
    ) -> Result<Option<PluginRecord>, ServiceError>;

    async fn delete_record(&self, record_id: Uuid) -> Result<bool, ServiceError>;

    async fn get_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> Result<Option<serde_json::Value>, ServiceError>;

    async fn put_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), ServiceError>;
}

#[async_trait]
impl PluginDataServiceFacade for PluginDataService {
    async fn list_records(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PluginRecord>, ServiceError> {
        self.list_records(plugin, scope, scope_id, kind, limit, offset)
            .await
    }

    async fn create_record(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        data: &serde_json::Value,
    ) -> Result<PluginRecord, ServiceError> {
        self.create_record(plugin, scope, scope_id, kind, data)
            .await
    }

    async fn get_record(&self, record_id: Uuid) -> Result<Option<PluginRecord>, ServiceError> {
        self.get_record(record_id).await
    }

    async fn update_record(
        &self,
        record_id: Uuid,
        patch: &serde_json::Value,
    ) -> Result<Option<PluginRecord>, ServiceError> {
        self.update_record(record_id, patch).await
    }

    async fn delete_record(&self, record_id: Uuid) -> Result<bool, ServiceError> {
        self.delete_record(record_id).await
    }

    async fn get_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> Result<Option<serde_json::Value>, ServiceError> {
        self.get_kv(plugin, scope, scope_id, key).await
    }

    async fn put_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), ServiceError> {
        self.put_kv(plugin, scope, scope_id, key, value).await
    }
}

impl PluginDataService {
    pub fn new(repo: Arc<dyn PluginRepository>) -> Self {
        Self { repo }
    }

    pub async fn list_records(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PluginRecord>, ServiceError> {
        let uc = ListPluginRecords {
            repo: self.repo.as_ref(),
        };
        uc.execute(plugin, scope, scope_id, kind, limit, offset)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_record(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        data: &serde_json::Value,
    ) -> Result<PluginRecord, ServiceError> {
        let uc = CreatePluginRecord {
            repo: self.repo.as_ref(),
        };
        uc.execute(plugin, scope, scope_id, kind, data)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_record(&self, record_id: Uuid) -> Result<Option<PluginRecord>, ServiceError> {
        let uc = GetPluginRecord {
            repo: self.repo.as_ref(),
        };
        uc.execute(record_id).await.map_err(ServiceError::from)
    }

    pub async fn update_record(
        &self,
        record_id: Uuid,
        patch: &serde_json::Value,
    ) -> Result<Option<PluginRecord>, ServiceError> {
        let uc = UpdatePluginRecord {
            repo: self.repo.as_ref(),
        };
        uc.execute(record_id, patch)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_record(&self, record_id: Uuid) -> Result<bool, ServiceError> {
        let uc = DeletePluginRecord {
            repo: self.repo.as_ref(),
        };
        uc.execute(record_id).await.map_err(ServiceError::from)
    }

    pub async fn get_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> Result<Option<serde_json::Value>, ServiceError> {
        let uc = GetPluginKv {
            repo: self.repo.as_ref(),
        };
        uc.execute(plugin, scope, scope_id, key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn put_kv(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), ServiceError> {
        let uc = PutPluginKv {
            repo: self.repo.as_ref(),
        };
        uc.execute(plugin, scope, scope_id, key, value)
            .await
            .map_err(ServiceError::from)
    }
}
