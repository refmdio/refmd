use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::application::ports::api_token_repository::ApiToken;

#[derive(Debug, Clone)]
pub struct ApiTokenDto {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreatedApiTokenDto {
    pub token: ApiTokenDto,
    pub plaintext: String,
}

impl From<ApiToken> for ApiTokenDto {
    fn from(value: ApiToken) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
        }
    }
}
