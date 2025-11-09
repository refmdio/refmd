use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::application::ports::user_shortcut_repository::UserShortcutProfile;

#[derive(Debug, Clone)]
pub struct UserShortcutProfileDto {
    pub user_id: Uuid,
    pub bindings: Value,
    pub leader_key: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserShortcutProfile> for UserShortcutProfileDto {
    fn from(value: UserShortcutProfile) -> Self {
        Self {
            user_id: value.user_id,
            bindings: value.bindings,
            leader_key: value.leader_key,
            updated_at: value.updated_at,
        }
    }
}
