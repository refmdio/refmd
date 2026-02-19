//! Session-based authentication extractors and helpers

use application::dto::SessionDto;
use application::types::UserId;
use application::identity::{
    AuthenticateSessionError, AuthenticateSessionHandler, AuthenticateSessionQuery,
};
use axum::{
    Json,
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;
use crate::routes::auth::SESSION_COOKIE_NAME;
use crate::state::type_aliases::DynSessionRepository;

/// Authenticated user information extracted from session
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: UserId,
    pub session: SessionDto,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate(&parts.headers, &state.session_repo()).await
    }
}

/// Authentication error response
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    /// When true, this error represents an internal server error (500)
    /// rather than an authentication failure (401).
    #[serde(skip)]
    is_internal: bool,
}

impl AuthError {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            is_internal: false,
        }
    }

    pub fn missing_session() -> Self {
        Self::new("missing session cookie")
    }

    pub fn invalid_session() -> Self {
        Self::new("invalid session")
    }

    pub fn expired_session() -> Self {
        Self::new("session expired")
    }

    // PoP-specific constructors
    pub fn missing_header(name: &str) -> Self {
        Self::new(format!("missing {} header", name))
    }

    pub fn invalid_header(name: &str) -> Self {
        Self::new(format!("invalid {} header", name))
    }

    pub fn challenge_not_found() -> Self {
        Self::new("challenge not found or already used")
    }

    pub fn challenge_expired() -> Self {
        Self::new("challenge has expired")
    }

    pub fn device_revoked() -> Self {
        Self::new("device has been revoked")
    }

    pub fn invalid_signature() -> Self {
        Self::new("invalid signature")
    }

    pub fn unauthorized() -> Self {
        Self::new("unauthorized")
    }

    pub fn internal_error() -> Self {
        Self {
            error: "internal server error".into(),
            is_internal: true,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = if self.is_internal {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::UNAUTHORIZED
        };
        (status, Json(self)).into_response()
    }
}

/// Extract session token from cookie
pub fn extract_session_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(AuthError::missing_session)?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME))
            && !value.is_empty()
        {
            return Ok(value);
        }
    }

    Err(AuthError::missing_session())
}

/// Extract and hash the session token from request headers.
fn extract_auth_query(headers: &HeaderMap) -> Result<AuthenticateSessionQuery, AuthError> {
    let token = extract_session_token(headers)?;
    let token_hash = hash_session_token(token);
    Ok(AuthenticateSessionQuery { token_hash })
}

/// Authenticate request and return minimal user info (user_id + session).
pub(super) async fn authenticate(
    headers: &HeaderMap,
    session_repo: &DynSessionRepository,
) -> Result<AuthUser, AuthError> {
    let query = extract_auth_query(headers)?;
    let handler = AuthenticateSessionHandler::new(Arc::clone(session_repo));
    let result = handler.authenticate(&query).await.map_err(map_auth_error)?;

    Ok(AuthUser {
        user_id: result.user_id,
        session: result.session,
    })
}

fn map_auth_error(e: AuthenticateSessionError) -> AuthError {
    match e {
        AuthenticateSessionError::InvalidSession => AuthError::invalid_session(),
        AuthenticateSessionError::SessionExpired => AuthError::expired_session(),
        AuthenticateSessionError::Internal => AuthError::internal_error(),
    }
}

pub use application::identity::session_token::hash_session_token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_session_token() {
        let token = "test-token-123";
        let hash = hash_session_token(token);

        // Hash should be 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);

        // Same token should produce same hash
        assert_eq!(hash, hash_session_token(token));

        // Different token should produce different hash
        assert_ne!(hash, hash_session_token("different-token"));
    }

    #[test]
    fn test_extract_session_token() {
        use axum::http::HeaderValue;

        let mut headers = HeaderMap::new();

        // Missing cookie header
        assert!(extract_session_token(&headers).is_err());

        // Cookie header without session cookie
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other_cookie=value"),
        );
        assert!(extract_session_token(&headers).is_err());

        // Valid session cookie
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("refmd_session=my-token; other=value"),
        );
        assert_eq!(extract_session_token(&headers).unwrap(), "my-token");

        // Session cookie only
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("refmd_session=token123"),
        );
        assert_eq!(extract_session_token(&headers).unwrap(), "token123");
    }
}
