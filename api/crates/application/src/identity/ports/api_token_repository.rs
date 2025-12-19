use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct ApiTokenSecret {
    pub token: ApiToken,
    pub token_hash: String,
    pub token_digest: String,
}

#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(
        &self,
        workspace_id: Uuid,
        owner_id: Uuid,
        name: &str,
        token_hash: &str,
        token_digest: &str,
    ) -> PortResult<ApiToken>;

    async fn list_active(&self, workspace_id: Uuid) -> PortResult<Vec<ApiToken>>;

    async fn revoke(&self, workspace_id: Uuid, token_id: Uuid) -> PortResult<bool>;

    async fn find_by_digest(&self, digest: &str) -> PortResult<Option<ApiTokenSecret>>;

    async fn touch_last_used(&self, token_id: Uuid) -> PortResult<()>;
}
