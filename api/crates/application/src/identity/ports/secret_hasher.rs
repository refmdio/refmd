pub trait SecretHasher: Send + Sync {
    fn hash_secret(&self, secret: &str) -> anyhow::Result<String>;
    fn verify_secret(&self, secret: &str, secret_hash: &str) -> anyhow::Result<bool>;
}
