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
    #[allow(dead_code)]
    exp: usize,
}

impl AuthService {
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
        if let Ok(data) = jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        ) {
            return Ok(Some(data.claims.sub));
        }

        self.tokens
            .validate(token)
            .await
            .map(|opt| opt.map(|uuid| uuid.to_string()))
    }

    pub fn issue_session(&self, user_id: Uuid) -> Result<IssuedSession, ServiceError> {
        let now = Utc::now().timestamp() as usize;
        let exp = now + self.jwt_expires_secs;
        let claims = Claims {
            sub: user_id.to_string(),
            exp,
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
