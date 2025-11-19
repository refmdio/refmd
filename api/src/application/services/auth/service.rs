use std::sync::Arc;

use anyhow::Error as AnyError;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::application::services::auth::token_validation::TokenValidationService;
use crate::application::services::errors::ServiceError;

#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
    tokens: Arc<TokenValidationService>,
    jwt_expires_secs: usize,
}

#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub token: String,
    pub expires_at: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    iat: usize,
    #[allow(dead_code)]
    exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
}

impl AuthService {
    fn decode_claims(&self, token: &str) -> Option<Claims> {
        jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .ok()
        .map(|data| data.claims)
    }

    pub fn new(
        jwt_secret: impl Into<String>,
        tokens: Arc<TokenValidationService>,
        jwt_expires_secs: usize,
    ) -> Self {
        Self {
            jwt_secret: jwt_secret.into(),
            tokens,
            jwt_expires_secs,
        }
    }

    pub async fn subject_from_token(&self, token: &str) -> Result<Option<String>, ServiceError> {
        if let Some(claims) = self.decode_claims(token) {
            return Ok(Some(claims.sub));
        }

        self.tokens
            .validate(token)
            .await
            .map(|opt| opt.map(|(user_id, _)| user_id.to_string()))
    }

    pub fn workspace_from_token_claim(&self, token: &str) -> Option<Uuid> {
        self.decode_claims(token)
            .and_then(|claims| claims.workspace_id)
            .and_then(|raw| Uuid::parse_str(&raw).ok())
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
            .map(|opt| opt.map(|(_, workspace_id)| workspace_id))
    }

    pub fn issue_session(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        session_id: Option<Uuid>,
    ) -> Result<IssuedSession, ServiceError> {
        let now = Utc::now().timestamp() as usize;
        let exp = now + self.jwt_expires_secs;
        let claims = Claims {
            sub: user_id.to_string(),
            workspace_id: Some(workspace_id.to_string()),
            iat: now,
            exp,
            sid: session_id.map(|id| id.to_string()),
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|err| ServiceError::Unexpected(AnyError::new(err)))?;
        Ok(IssuedSession {
            token,
            expires_at: exp,
        })
    }

    pub fn session_ttl_secs(&self) -> usize {
        self.jwt_expires_secs
    }
}
