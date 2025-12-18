use std::sync::Arc;

use crate::core::services::errors::ServiceError;
use crate::identity::ports::api_token_repository::ApiTokenRepository;
use crate::identity::services::api_tokens::{compute_digest, verify_token};
use domain::identity::api_token::ApiTokenSubject;

pub struct TokenValidationService {
    repo: Arc<dyn ApiTokenRepository>,
}

impl TokenValidationService {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    pub async fn validate(&self, token: &str) -> Result<Option<ApiTokenSubject>, ServiceError> {
        let digest = compute_digest(token);
        let record = self
            .repo
            .find_by_digest(&digest)
            .await
            .map_err(ServiceError::from)?;
        let Some(secret) = record else {
            return Ok(None);
        };
        if secret.token.revoked_at.is_some() {
            return Ok(None);
        }
        let ok = verify_token(token, &secret.token_hash).map_err(ServiceError::from)?;
        if !ok {
            return Ok(None);
        }
        self.repo
            .touch_last_used(secret.token.id)
            .await
            .map_err(ServiceError::from)?;
        Ok(Some(ApiTokenSubject {
            owner_id: secret.token.owner_id,
            workspace_id: secret.token.workspace_id,
        }))
    }
}
