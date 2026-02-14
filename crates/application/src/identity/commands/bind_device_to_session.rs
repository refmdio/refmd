//! Bind device to session command
//!
//! Binds a device_id to an existing session (used after PoP verification).

use domain::encryption::DeviceId;
use domain::identity::{SessionId, SessionRepository};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::SessionDto;

/// Bind device to session command
#[derive(Debug)]
pub struct BindDeviceToSessionCommand {
    pub session_id: SessionId,
    pub device_id: DeviceId,
}

/// Bind device to session error
#[derive(Debug, Error)]
pub enum BindDeviceToSessionError<SR: std::error::Error> {
    #[error("session not found")]
    SessionNotFound,
    #[error("session repository error: {0}")]
    SessionRepository(SR),
}

/// Bind device to session handler
pub struct BindDeviceToSessionHandler<SR: ?Sized> {
    session_repo: Arc<SR>,
}

impl<SR> BindDeviceToSessionHandler<SR>
where
    SR: SessionRepository + ?Sized,
{
    pub fn new(session_repo: Arc<SR>) -> Self {
        Self { session_repo }
    }

    pub async fn handle(
        &self,
        command: BindDeviceToSessionCommand,
    ) -> Result<SessionDto, BindDeviceToSessionError<SR::Error>> {
        let mut session = self
            .session_repo
            .find_by_id(command.session_id)
            .await
            .map_err(BindDeviceToSessionError::SessionRepository)?
            .ok_or(BindDeviceToSessionError::SessionNotFound)?;

        session.bind_device(command.device_id);

        self.session_repo
            .save(&session)
            .await
            .map_err(BindDeviceToSessionError::SessionRepository)?;

        Ok(session.into())
    }
}
