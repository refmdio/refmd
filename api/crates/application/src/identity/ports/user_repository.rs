use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub password_hash: Option<String>,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(
        &self,
        id: Uuid,
        email: &str,
        name: &str,
        password_hash: Option<&str>,
        default_workspace_id: Uuid,
    ) -> PortResult<UserRow>;
    async fn find_by_email(&self, email: &str) -> PortResult<Option<UserRow>>;
    async fn find_by_external_identity(
        &self,
        provider: &str,
        subject: &str,
    ) -> PortResult<Option<UserRow>>;
    async fn find_by_id(&self, id: Uuid) -> PortResult<Option<UserRow>>;
    async fn link_external_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
    ) -> PortResult<()>;
    async fn delete_user(&self, id: Uuid) -> PortResult<bool>;
    async fn list_user_ids(&self) -> PortResult<Vec<Uuid>>;
}
