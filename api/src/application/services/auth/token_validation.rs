use std::sync::Arc;

use uuid::Uuid;

use crate::application::ports::api_token_repository::ApiTokenRepository;
use crate::application::services::api_tokens::{compute_digest, verify_token};
use crate::application::services::errors::ServiceError;

pub struct TokenValidationService {
    repo: Arc<dyn ApiTokenRepository>,
}

impl TokenValidationService {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    pub async fn validate(&self, token: &str) -> Result<Option<(Uuid, Uuid)>, ServiceError> {
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
        Ok(Some((secret.token.owner_id, secret.token.workspace_id)))
    }
}
