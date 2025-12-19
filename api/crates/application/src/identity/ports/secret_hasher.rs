use crate::core::ports::errors::PortResult;

pub trait SecretHasher: Send + Sync {
    fn hash_secret(&self, secret: &str) -> PortResult<String>;
    fn verify_secret(&self, secret: &str, secret_hash: &str) -> PortResult<bool>;
}
