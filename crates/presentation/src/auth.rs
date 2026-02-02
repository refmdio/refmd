//! Authentication extractors and middleware
//!
//! Provides authentication helpers for authenticated requests.

use application::domain::identity::{Session, SessionRepository, User, UserId, UserRepository};
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::routes::auth::SESSION_COOKIE_NAME;

/// Authenticated user information extracted from session
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: UserId,
    pub session: Session,
}

/// Authenticated user with full user data
#[derive(Debug, Clone)]
pub struct AuthUserFull {
    pub user: User,
    pub session: Session,
}

/// Authentication error response
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
}

impl AuthError {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
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

    pub fn user_not_found() -> Self {
        Self::new("user not found")
    }

    pub fn internal_error() -> Self {
        Self::new("internal server error")
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
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

/// Authenticate request using session repository
///
/// This function validates the session token from the HttpOnly cookie
/// and returns the authenticated user information.
pub async fn authenticate<S: SessionRepository>(
    headers: &HeaderMap,
    session_repo: &S,
) -> Result<AuthUser, AuthError> {
    let token = extract_session_token(headers)?;
    let token_hash = hash_session_token(token);

    let session = session_repo
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|_| AuthError::internal_error())?
        .ok_or_else(AuthError::invalid_session)?;

    if session.is_expired() {
        return Err(AuthError::expired_session());
    }

    Ok(AuthUser {
        user_id: session.user_id,
        session,
    })
}

/// Authenticate request and load full user data
pub async fn authenticate_full<S: SessionRepository, U: UserRepository>(
    headers: &HeaderMap,
    session_repo: &S,
    user_repo: &U,
) -> Result<AuthUserFull, AuthError> {
    let auth_user = authenticate(headers, session_repo).await?;

    let user = user_repo
        .find_by_id(auth_user.user_id)
        .await
        .map_err(|_| AuthError::internal_error())?
        .ok_or_else(AuthError::user_not_found)?;

    Ok(AuthUserFull {
        user,
        session: auth_user.session,
    })
}

/// Hash session token for storage/lookup
pub fn hash_session_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in hash {
        std::fmt::Write::write_fmt(&mut hex, format_args!("{:02x}", b))
            .expect("Failed to write hex");
    }
    hex
}

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
