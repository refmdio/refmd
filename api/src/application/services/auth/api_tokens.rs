use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use sha2::{Digest, Sha256};

pub struct GeneratedApiToken {
    pub plaintext: String,
    pub token_hash: String,
    pub token_digest: String,
}

pub fn generate_api_token() -> anyhow::Result<GeneratedApiToken> {
    let random: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    let plaintext = format!("rmd_{random}");

    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    let digest = compute_digest(&plaintext);

    Ok(GeneratedApiToken {
        plaintext,
        token_hash: hash,
        token_digest: digest,
    })
}

pub fn compute_digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_token(token: &str, token_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(token_hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok())
}
