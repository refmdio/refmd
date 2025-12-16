use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::api_tokens::{ApiTokenDto, CreatedApiTokenDto};

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenItem {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<ApiTokenDto> for ApiTokenItem {
    fn from(value: ApiTokenDto) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenCreateResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub token: String,
}

impl From<CreatedApiTokenDto> for ApiTokenCreateResponse {
    fn from(value: CreatedApiTokenDto) -> Self {
        Self {
            id: value.token.id,
            name: value.token.name,
            created_at: value.token.created_at,
            token: value.plaintext,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApiTokenCreateRequest {
    #[schema(example = "Deploy token")]
    pub name: Option<String>,
}
