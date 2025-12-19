use application::core::ports::errors::PortResult;
use application::identity::ports::secret_hasher::SecretHasher;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use password_hash::rand_core::OsRng;

#[derive(Debug, Default)]
pub struct Argon2SecretHasher;

impl SecretHasher for Argon2SecretHasher {
    fn hash_secret(&self, secret: &str) -> PortResult<String> {
        let out: anyhow::Result<String> = (|| {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(secret.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .to_string();
            Ok(hash)
        })();
        out.map_err(Into::into)
    }

    fn verify_secret(&self, secret: &str, secret_hash: &str) -> PortResult<bool> {
        let out: anyhow::Result<bool> = (|| {
            let parsed =
                PasswordHash::new(secret_hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Ok(Argon2::default()
                .verify_password(secret.as_bytes(), &parsed)
                .is_ok())
        })();
        out.map_err(Into::into)
    }
}
