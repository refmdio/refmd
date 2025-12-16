use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

use crate::application::dto::user_shortcuts::UserShortcutProfileDto;

#[derive(Debug, Serialize, ToSchema)]
pub struct UserShortcutResponse {
    #[schema(value_type = Object)]
    pub bindings: Value,
    #[schema(example = "<Space>")]
    pub leader_key: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl UserShortcutResponse {
    pub fn empty() -> Self {
        Self {
            bindings: Value::Object(Map::new()),
            leader_key: None,
            updated_at: None,
        }
    }
}

impl From<UserShortcutProfileDto> for UserShortcutResponse {
    fn from(value: UserShortcutProfileDto) -> Self {
        Self {
            bindings: value.bindings,
            leader_key: value.leader_key,
            updated_at: Some(value.updated_at),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserShortcutRequest {
    #[schema(value_type = Object)]
    #[serde(default = "Value::default")]
    pub bindings: Value,
    #[schema(example = "<Space>")]
    pub leader_key: Option<String>,
}
