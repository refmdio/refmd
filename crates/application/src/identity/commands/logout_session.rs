//! Logout session command
//!
//! Finds a session by token hash and deletes it.
//! Session deletion must be reliable.

use domain::identity::SessionRepository;
use std::sync::Arc;
use thiserror::Error;

/// Logout session command
pub struct LogoutSessionCommand {
    pub token_hash: String,
}

/// Logout session error
#[derive(Debug, Error)]
pub enum LogoutSessionError<SR: std::error::Error> {
    #[error("session repository error: {0}")]
    SessionRepository(SR),
}

crate::types::impl_app_error!(
    [SR: std::error::Error]
    LogoutSessionError<SR>,
);

/// Logout session handler
pub struct LogoutSessionHandler<SR: ?Sized> {
    session_repo: Arc<SR>,
}

impl<SR> LogoutSessionHandler<SR>
where
    SR: SessionRepository + ?Sized,
{
    pub fn new(session_repo: Arc<SR>) -> Self {
        Self { session_repo }
    }

    /// Invalidate the session. Returns Ok(()) even if the session was already gone.
    pub async fn handle(
        &self,
        command: LogoutSessionCommand,
    ) -> Result<(), LogoutSessionError<SR::Error>> {
        let session = self
            .session_repo
            .find_by_token_hash(&command.token_hash)
            .await
            .map_err(LogoutSessionError::SessionRepository)?;

        if let Some(session) = session {
            self.session_repo
                .delete(session.id)
                .await
                .map_err(LogoutSessionError::SessionRepository)?;
        }

        Ok(())
    }
}
