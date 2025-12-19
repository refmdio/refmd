use std::sync::Arc;

use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::core::services::utils::hash::sha256_hex_str;
use crate::identity::dtos::{ApiTokenDto, CreatedApiTokenDto};
use crate::identity::ports::api_token_repository::ApiTokenRepository;
use crate::identity::ports::secret_hasher::SecretHasher;
use crate::identity::use_cases::api_tokens::create_token::CreateApiToken;
use crate::identity::use_cases::api_tokens::list_tokens::ListApiTokens;
use crate::identity::use_cases::api_tokens::revoke_token::RevokeApiToken;
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::identity::policy;

pub struct ApiTokenService {
    repo: Arc<dyn ApiTokenRepository>,
    hasher: Arc<dyn SecretHasher>,
}

#[async_trait]
pub trait ApiTokenServiceFacade: Send + Sync {
    async fn list(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ApiTokenDto>, ServiceError>;
    async fn create(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        name: Option<&str>,
    ) -> Result<CreatedApiTokenDto, ServiceError>;
    async fn revoke(
        &self,
        workspace_id: Uuid,
        id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError>;
}

#[async_trait]
impl ApiTokenServiceFacade for ApiTokenService {
    async fn list(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ApiTokenDto>, ServiceError> {
        self.list(workspace_id, permissions).await
    }

    async fn create(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        name: Option<&str>,
    ) -> Result<CreatedApiTokenDto, ServiceError> {
        self.create(workspace_id, user_id, permissions, name).await
    }

    async fn revoke(
        &self,
        workspace_id: Uuid,
        id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError> {
        self.revoke(workspace_id, id, permissions).await
    }
}

impl ApiTokenService {
    pub fn new(repo: Arc<dyn ApiTokenRepository>, hasher: Arc<dyn SecretHasher>) -> Self {
        Self { repo, hasher }
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
            hasher: self.hasher.as_ref(),
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
    policy::ensure_api_token_manage_allowed(permissions).map_err(|_| ServiceError::Forbidden)
}

pub struct GeneratedApiToken {
    pub plaintext: String,
    pub token_hash: String,
    pub token_digest: String,
}

pub fn generate_api_token(hasher: &dyn SecretHasher) -> anyhow::Result<GeneratedApiToken> {
    let random: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    let plaintext = format!("rmd_{random}");

    let hash = hasher.hash_secret(&plaintext)?;
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

pub fn verify_token(
    hasher: &dyn SecretHasher,
    token: &str,
    token_hash: &str,
) -> anyhow::Result<bool> {
    Ok(hasher.verify_secret(token, token_hash)?)
}
