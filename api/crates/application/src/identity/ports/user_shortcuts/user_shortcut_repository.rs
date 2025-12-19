use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct UserShortcutProfile {
    pub user_id: Uuid,
    pub bindings: Value,
    pub leader_key: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait UserShortcutRepository: Send + Sync {
    async fn get_by_user(&self, user_id: Uuid) -> PortResult<Option<UserShortcutProfile>>;

    async fn upsert(
        &self,
        user_id: Uuid,
        bindings: Value,
        leader_key: Option<String>,
    ) -> PortResult<UserShortcutProfile>;
}
