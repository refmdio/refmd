use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use uuid::Uuid;

use crate::identity::dtos::{ApiTokenDto, CreatedApiTokenDto};
use crate::identity::ports::api_token_repository::ApiTokenRepository;
use crate::core::services::errors::ServiceError;
use crate::identity::use_cases::api_tokens::create_token::CreateApiToken;
use crate::identity::use_cases::api_tokens::list_tokens::ListApiTokens;
use crate::identity::use_cases::api_tokens::revoke_token::RevokeApiToken;
use crate::core::services::utils::hash::sha256_hex_str;
use domain::workspaces::permissions::{PERM_API_TOKEN_MANAGE, PermissionSet};

pub struct ApiTokenService {
    repo: Arc<dyn ApiTokenRepository>,
}

impl ApiTokenService {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    pub async fn list(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ApiTokenDto>, ServiceError> {
        ensure_api_token_permission(workspace_id, permissions)?;
        let uc = ListApiTokens {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn create(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        name: Option<&str>,
    ) -> Result<CreatedApiTokenDto, ServiceError> {
        ensure_api_token_permission(workspace_id, permissions)?;
        let uc = CreateApiToken {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, user_id, name)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn revoke(
        &self,
        workspace_id: Uuid,
        id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError> {
        ensure_api_token_permission(workspace_id, permissions)?;
        let uc = RevokeApiToken {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, id)
            .await
            .map_err(ServiceError::from)
    }
}

fn ensure_api_token_permission(
    _workspace_id: Uuid,
    permissions: &PermissionSet,
) -> Result<(), ServiceError> {
    if permissions.allows(PERM_API_TOKEN_MANAGE) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
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
    sha256_hex_str(token)
}

pub fn verify_token(token: &str, token_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(token_hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok())
}
