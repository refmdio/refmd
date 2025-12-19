use uuid::Uuid;

use crate::identity::ports::secret_hasher::SecretHasher;
use crate::identity::ports::user_repository::{UserRepository, UserRow};

pub struct Register<'a, R: UserRepository + ?Sized> {
    pub repo: &'a R,
    pub hasher: &'a dyn SecretHasher,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub password: String,
    pub default_workspace_id: Uuid,
}

impl<'a, R: UserRepository + ?Sized> Register<'a, R> {
    pub async fn execute(&self, req: &RegisterRequest) -> anyhow::Result<UserRow> {
        let hash = self.hasher.hash_secret(&req.password)?;
        let user = self
            .repo
            .create_user(
                req.id,
                &req.email,
                &req.name,
                Some(&hash),
                req.default_workspace_id,
            )
            .await?;
        Ok(user)
    }
}
