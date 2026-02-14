//! Verify PoP and bind device to session
//!
//! Combines PoP verification with session device binding.
//! If the session does not yet have a device_id, it is automatically bound
//! after successful PoP verification. This keeps the binding logic
//! in the application layer rather than the presentation extractor.

use crate::dto::{DeviceDto, SessionDto};
use crate::encryption::{VerifyPopCommand, VerifyPopError, VerifyPopHandler};
use crate::identity::{BindDeviceToSessionCommand, BindDeviceToSessionHandler};
use domain::encryption::DeviceRepository;
use domain::identity::SessionRepository;
use domain::pop::ChallengeStore;
use std::sync::Arc;
use thiserror::Error;

/// Verify PoP and bind result
pub struct VerifyPopAndBindResult {
    pub session: SessionDto,
    pub device: DeviceDto,
}

/// Verify PoP and bind error
#[derive(Debug, Error)]
pub enum VerifyPopAndBindError<DR: std::error::Error> {
    #[error(transparent)]
    Pop(VerifyPopError<DR>),

    #[error("failed to bind device to session: {0}")]
    BindFailed(String),
}

/// Verify PoP and bind handler
pub struct VerifyPopAndBindHandler<DR: ?Sized, SR: ?Sized> {
    device_repo: Arc<DR>,
    session_repo: Arc<SR>,
    challenge_store: Arc<dyn ChallengeStore>,
}

impl<DR, SR> VerifyPopAndBindHandler<DR, SR>
where
    DR: DeviceRepository + ?Sized,
    SR: SessionRepository + ?Sized,
{
    pub fn new(
        device_repo: Arc<DR>,
        session_repo: Arc<SR>,
        challenge_store: Arc<dyn ChallengeStore>,
    ) -> Self {
        Self {
            device_repo,
            session_repo,
            challenge_store,
        }
    }

    pub async fn handle(
        &self,
        command: VerifyPopCommand,
        session: SessionDto,
    ) -> Result<VerifyPopAndBindResult, VerifyPopAndBindError<DR::Error>> {
        // 1. Verify PoP
        let pop_handler =
            VerifyPopHandler::new(self.device_repo.clone(), self.challenge_store.clone());
        let device = pop_handler.handle(command).await.map_err(VerifyPopAndBindError::Pop)?;

        // 2. Auto-bind device_id to session if not yet set
        let session = if session.device_id.is_none() {
            let bind_handler = BindDeviceToSessionHandler::new(self.session_repo.clone());
            bind_handler
                .handle(BindDeviceToSessionCommand {
                    session_id: session.id,
                    device_id: device.id,
                })
                .await
                .map_err(|e| VerifyPopAndBindError::BindFailed(e.to_string()))?
        } else {
            session
        };

        Ok(VerifyPopAndBindResult { session, device })
    }
}
