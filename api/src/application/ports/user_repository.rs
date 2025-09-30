use async_trait::async_trait;
use uuid::Uuid;

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
        email: &str,
        name: &str,
        password_hash: &str,
    ) -> anyhow::Result<UserRow>;
    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<UserRow>>;
    async fn find_by_id(&self, id: Uuid) -> anyhow::Result<Option<UserRow>>;
    async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool>;
}
