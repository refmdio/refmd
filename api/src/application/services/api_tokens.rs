use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::application::dto::api_tokens::{ApiTokenDto, CreatedApiTokenDto};
use crate::application::ports::api_token_repository::ApiTokenRepository;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::api_tokens::create_token::CreateApiToken;
use crate::application::use_cases::api_tokens::list_tokens::ListApiTokens;
use crate::application::use_cases::api_tokens::revoke_token::RevokeApiToken;

pub struct ApiTokenService {
    repo: Arc<dyn ApiTokenRepository>,
}

impl ApiTokenService {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, user_id: Uuid) -> Result<Vec<ApiTokenDto>, ServiceError> {
        let uc = ListApiTokens {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn create(
        &self,
        user_id: Uuid,
        name: Option<&str>,
    ) -> Result<CreatedApiTokenDto, ServiceError> {
        let uc = CreateApiToken {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, name).await.map_err(ServiceError::from)
    }

    pub async fn revoke(&self, user_id: Uuid, id: Uuid) -> Result<bool, ServiceError> {
        let uc = RevokeApiToken {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, id).await.map_err(ServiceError::from)
    }
}

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
