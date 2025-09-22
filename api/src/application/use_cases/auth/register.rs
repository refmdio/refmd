use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use password_hash::rand_core::OsRng;

use crate::application::ports::user_repository::{UserRepository, UserRow};

pub struct Register<'a, R: UserRepository + ?Sized> {
    pub repo: &'a R,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub email: String,
    pub name: String,
    pub password: String,
}

impl<'a, R: UserRepository + ?Sized> Register<'a, R> {
    pub async fn execute(&self, req: &RegisterRequest) -> anyhow::Result<UserRow> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .to_string();
        let user = self.repo.create_user(&req.email, &req.name, &hash).await?;
        Ok(user)
    }
}
