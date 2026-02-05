//! Authentication middleware
//!
//! Tower middleware for session token validation.

use std::sync::Arc;

use axum::{
    Json,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use application::domain::identity::SessionRepository;

use crate::auth::{extract_session_token, hash_session_token};

/// Error response for auth failures
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
}

/// Authentication middleware that validates session token from cookie
pub async fn require_auth<S>(session_repo: Arc<S>, req: Request, next: Next) -> Response
where
    S: SessionRepository + Send + Sync + 'static,
{
    // Extract session token from cookie
    let token = match extract_session_token(req.headers()) {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(AuthError { error: e.error })).into_response();
        }
    };

    // Hash the token and validate session
    let token_hash = hash_session_token(token);

    let session = match session_repo.find_by_token_hash(&token_hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid or expired session".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Check session expiration
    if session.is_expired() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "session expired".to_string(),
            }),
        )
            .into_response();
    }

    next.run(req).await
}
