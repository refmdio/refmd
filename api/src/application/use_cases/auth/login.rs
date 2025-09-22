use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};

use crate::application::ports::user_repository::{UserRepository, UserRow};

pub struct Login<'a, R: UserRepository + ?Sized> {
    pub repo: &'a R,
}

#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl<'a, R: UserRepository + ?Sized> Login<'a, R> {
    pub async fn execute(&self, req: &LoginRequest) -> anyhow::Result<Option<UserRow>> {
        let row = match self.repo.find_by_email(&req.email).await? {
            Some(r) => r,
            None => return Ok(None),
        };
        let hash = row.password_hash.clone().unwrap_or_default();
        let parsed = PasswordHash::new(&hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed)
            .is_ok()
        {
            Ok(Some(UserRow {
                id: row.id,
                email: row.email,
                name: row.name,
                password_hash: None,
            }))
        } else {
            Ok(None)
        }
    }
}
