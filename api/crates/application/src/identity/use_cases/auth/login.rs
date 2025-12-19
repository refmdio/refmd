use crate::identity::ports::secret_hasher::SecretHasher;
use crate::identity::ports::user_repository::{UserRepository, UserRow};

pub struct Login<'a, R: UserRepository + ?Sized> {
    pub repo: &'a R,
    pub hasher: &'a dyn SecretHasher,
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
        let hash = match row.password_hash.as_deref() {
            Some(hash) if !hash.is_empty() => hash,
            _ => return Ok(None),
        };
        if self.hasher.verify_secret(&req.password, hash)? {
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
