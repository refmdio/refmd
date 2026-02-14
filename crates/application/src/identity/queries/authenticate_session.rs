//! Session authentication query
//!
//! Validates a session token hash and returns the authenticated user.

use domain::identity::{SessionRepository, UserId};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::SessionDto;

/// Authenticate session query
pub struct AuthenticateSessionQuery {
    /// Hashed session token (SHA-256 hex)
    pub token_hash: String,
}

/// Authenticate session result (lightweight, no user data)
pub struct AuthenticateSessionResult {
    pub user_id: UserId,
    pub session: SessionDto,
}

/// Authenticate session error
#[derive(Debug, Error)]
pub enum AuthenticateSessionError {
    #[error("invalid session")]
    InvalidSession,
    #[error("session expired")]
    SessionExpired,
    #[error("internal error")]
    Internal,
}

impl crate::types::AppError for AuthenticateSessionError {
    fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            AuthenticateSessionError::InvalidSession
                | AuthenticateSessionError::SessionExpired
        )
    }
}

/// Session authentication handler
pub struct AuthenticateSessionHandler<SR: ?Sized> {
    session_repo: Arc<SR>,
}

impl<SR: ?Sized> AuthenticateSessionHandler<SR>
where
    SR: SessionRepository,
{
    pub fn new(session_repo: Arc<SR>) -> Self {
        Self { session_repo }
    }

    /// Authenticate session (lightweight, no user fetch)
    pub async fn authenticate(
        &self,
        query: &AuthenticateSessionQuery,
    ) -> Result<AuthenticateSessionResult, AuthenticateSessionError> {
        let session = self
            .session_repo
            .find_by_token_hash(&query.token_hash)
            .await
            .map_err(|_| AuthenticateSessionError::Internal)?
            .ok_or(AuthenticateSessionError::InvalidSession)?;

        if session.is_expired() {
            return Err(AuthenticateSessionError::SessionExpired);
        }

        let user_id = session.user_id;
        Ok(AuthenticateSessionResult {
            user_id,
            session: session.into(),
        })
    }
}
