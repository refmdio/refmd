//! Create PoP challenge command
//!
//! Generates a server-issued challenge for device Proof of Possession verification.

use chrono::{Duration, Utc};
use domain::encryption::{DeviceId, DeviceRepository};
use domain::identity::UserId;
use domain::pop::ChallengeStore;
use std::sync::Arc;
use thiserror::Error;

/// Challenge TTL in seconds (5 minutes)
const CHALLENGE_TTL_SECS: i64 = 300;

/// Create PoP challenge command
#[derive(Debug)]
pub struct CreatePopChallengeCommand {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

/// Create PoP challenge result
pub struct CreatePopChallengeResult {
    pub challenge: [u8; 32],
    pub expires_at: chrono::DateTime<Utc>,
}

/// Create PoP challenge error
#[derive(Debug, Error)]
pub enum CreatePopChallengeError {
    #[error("device not found")]
    DeviceNotFound,

    #[error("device has been revoked")]
    DeviceRevoked,

    #[error("internal error")]
    Internal,
}

crate::types::impl_app_error!(CreatePopChallengeError,
    not_found: [CreatePopChallengeError::DeviceNotFound],
    invalid_input: [CreatePopChallengeError::DeviceRevoked],
);

/// Create PoP challenge handler
pub struct CreatePopChallengeHandler<DR: ?Sized> {
    device_repo: Arc<DR>,
    challenge_store: Arc<dyn ChallengeStore>,
}

impl<DR: ?Sized> CreatePopChallengeHandler<DR>
where
    DR: DeviceRepository,
{
    pub fn new(device_repo: Arc<DR>, challenge_store: Arc<dyn ChallengeStore>) -> Self {
        Self {
            device_repo,
            challenge_store,
        }
    }

    pub async fn handle(
        &self,
        command: CreatePopChallengeCommand,
    ) -> Result<CreatePopChallengeResult, CreatePopChallengeError> {
        use crate::util::device_ownership::check_active_device_ownership;

        // Verify device exists, belongs to user, and is not revoked
        check_active_device_ownership(&self.device_repo, command.device_id, command.user_id)
            .await
            .map_err(|e| e.map_to(
                || CreatePopChallengeError::DeviceNotFound,
                || CreatePopChallengeError::DeviceRevoked,
                |_| CreatePopChallengeError::Internal,
            ))?;

        // Generate random 32-byte challenge using CSPRNG
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| CreatePopChallengeError::Internal)?;

        let expires_at = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS);

        // Store challenge
        self.challenge_store
            .store(command.device_id, challenge, expires_at)
            .await
            .map_err(|_| CreatePopChallengeError::Internal)?;

        Ok(CreatePopChallengeResult {
            challenge,
            expires_at,
        })
    }
}
