use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserSessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub remember_me: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserSessionSecret {
    pub session: UserSessionRecord,
    pub token_hash: String,
    pub token_digest: String,
}

#[async_trait]
pub trait UserSessionRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        token_hash: &str,
        token_digest: &str,
        expires_at: DateTime<Utc>,
        remember_me: bool,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> anyhow::Result<UserSessionRecord>;

    async fn find_by_digest(&self, token_digest: &str)
    -> anyhow::Result<Option<UserSessionSecret>>;

    #[allow(clippy::too_many_arguments)]
    async fn update_token(
        &self,
        session_id: Uuid,
        expected_token_digest: &str,
        token_hash: &str,
        token_digest: &str,
        expires_at: DateTime<Utc>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
        workspace_id: Option<Uuid>,
    ) -> anyhow::Result<bool>;

    async fn update_workspace(&self, session_id: Uuid, workspace_id: Uuid) -> anyhow::Result<bool>;

    async fn touch(&self, session_id: Uuid) -> anyhow::Result<()>;

    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<UserSessionRecord>>;

    async fn find_by_id(&self, session_id: Uuid) -> anyhow::Result<Option<UserSessionRecord>>;

    async fn revoke(&self, session_id: Uuid) -> anyhow::Result<bool>;

    async fn revoke_by_digest(&self, token_digest: &str) -> anyhow::Result<bool>;

    async fn revoke_all_for_user(&self, user_id: Uuid) -> anyhow::Result<()>;

    async fn delete_expired(&self, before: DateTime<Utc>, batch_size: i64) -> anyhow::Result<u64>;
}
