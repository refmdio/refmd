use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::identity::ports::jwt_codec::{JwtClaims, JwtCodec, JwtDecodeError};
use crate::identity::services::auth::token_validation::TokenValidationService;
use async_trait::async_trait;

#[derive(Clone)]
pub struct AuthService {
    jwt: Arc<dyn JwtCodec>,
    tokens: Arc<TokenValidationService>,
    jwt_expires_secs: usize,
}

#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub token: String,
    pub expires_at: usize,
}

#[async_trait]
pub trait AuthServiceFacade: Send + Sync {
    async fn subject_from_token(&self, token: &str) -> Result<Option<String>, ServiceError>;
    fn workspace_from_token_claim(&self, token: &str) -> Option<Uuid>;
    fn session_id_from_token_claim(&self, token: &str) -> Option<Uuid>;
    async fn workspace_from_token_async(&self, token: &str) -> Result<Option<Uuid>, ServiceError>;
    fn session_ttl_secs(&self) -> usize;
}

#[async_trait]
impl AuthServiceFacade for AuthService {
    async fn subject_from_token(&self, token: &str) -> Result<Option<String>, ServiceError> {
        self.subject_from_token(token).await
    }

    fn workspace_from_token_claim(&self, token: &str) -> Option<Uuid> {
        self.workspace_from_token_claim(token)
    }

    fn session_id_from_token_claim(&self, token: &str) -> Option<Uuid> {
        self.session_id_from_token_claim(token)
    }

    async fn workspace_from_token_async(&self, token: &str) -> Result<Option<Uuid>, ServiceError> {
        self.workspace_from_token_async(token).await
    }

    fn session_ttl_secs(&self) -> usize {
        self.session_ttl_secs()
    }
}

impl AuthService {
    pub fn new(
        jwt: Arc<dyn JwtCodec>,
        tokens: Arc<TokenValidationService>,
        jwt_expires_secs: usize,
    ) -> Self {
        Self {
            jwt,
            tokens,
            jwt_expires_secs,
        }
    }

    pub async fn subject_from_token(&self, token: &str) -> Result<Option<String>, ServiceError> {
        match self.jwt.decode(token) {
            Ok(claims) => return Ok(Some(claims.sub.to_string())),
            Err(JwtDecodeError::Expired) => return Err(ServiceError::TokenExpired),
            Err(JwtDecodeError::Invalid) => {}
        };

        self.tokens
            .validate(token)
            .await
            .map(|opt| opt.map(|subject| subject.owner_id.to_string()))
    }

    pub fn workspace_from_token_claim(&self, token: &str) -> Option<Uuid> {
        self.jwt
            .decode(token)
            .ok()
            .and_then(|claims| claims.workspace_id)
    }

    pub fn session_id_from_token_claim(&self, token: &str) -> Option<Uuid> {
        self.jwt.decode(token).ok().and_then(|claims| claims.sid)
    }

    pub async fn workspace_from_token_async(
        &self,
        token: &str,
    ) -> Result<Option<Uuid>, ServiceError> {
        if let Some(id) = self.workspace_from_token_claim(token) {
            return Ok(Some(id));
        }
        self.tokens
            .validate(token)
            .await
            .map(|opt| opt.map(|subject| subject.workspace_id))
    }

    pub fn issue_session(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        session_id: Option<Uuid>,
    ) -> Result<IssuedSession, ServiceError> {
        let now = Utc::now().timestamp() as usize;
        let exp = now + self.jwt_expires_secs;
        let claims = JwtClaims {
            sub: user_id,
            workspace_id: Some(workspace_id),
            iat: now,
            exp,
            sid: session_id,
        };
        let token = self
            .jwt
            .encode(&claims)
            .map_err(|_| ServiceError::Unexpected(anyhow::anyhow!("jwt_encode_failed")))?;
        Ok(IssuedSession {
            token,
            expires_at: exp,
        })
    }

    pub fn session_ttl_secs(&self) -> usize {
        self.jwt_expires_secs
    }
}
