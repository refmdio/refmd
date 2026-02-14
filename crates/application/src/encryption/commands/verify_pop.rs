//! PoP (Proof of Possession) verification command
//!
//! Verifies device ownership via a server-issued challenge.
//! Checks device exists, belongs to user, is not revoked,
//! verifies Ed25519 signature, and consumes the one-time challenge.

use crate::dto::DeviceDto;
use domain::encryption::{DeviceId, DeviceRepository};
use domain::identity::UserId;
use domain::pop::{ChallengeError, ChallengeStore};
use domain::signature::build_pop_signature_message;
use std::sync::Arc;
use thiserror::Error;

/// PoP verification command (pre-parsed from HTTP headers)
pub struct VerifyPopCommand {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Base64url-encoded challenge string (needed for signature message)
    pub challenge_str: String,
    /// Decoded 32-byte challenge
    pub challenge_bytes: [u8; 32],
    /// Decoded 64-byte Ed25519 signature
    pub signature_bytes: [u8; 64],
    /// String form of device_id (needed for signature message)
    pub device_id_str: String,
}

/// PoP verification error
#[derive(Debug, Error)]
pub enum VerifyPopError<DR: std::error::Error> {
    #[error("device not found or unauthorized")]
    Unauthorized,
    #[error("device has been revoked")]
    DeviceRevoked,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("challenge not found or already used")]
    ChallengeNotFound,
    #[error("challenge has expired")]
    ChallengeExpired,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("device repository error: {0}")]
    DeviceRepository(DR),
}

/// PoP verification handler
pub struct VerifyPopHandler<DR: ?Sized> {
    device_repo: Arc<DR>,
    challenge_store: Arc<dyn ChallengeStore>,
}

impl<DR> VerifyPopHandler<DR>
where
    DR: DeviceRepository + ?Sized,
{
    pub fn new(device_repo: Arc<DR>, challenge_store: Arc<dyn ChallengeStore>) -> Self {
        Self {
            device_repo,
            challenge_store,
        }
    }

    pub async fn handle(
        &self,
        command: VerifyPopCommand,
    ) -> Result<DeviceDto, VerifyPopError<DR::Error>> {
        use crate::util::device_ownership::check_active_device_ownership;

        // Verify device exists, belongs to user, and is not revoked
        let device = check_active_device_ownership(
            &self.device_repo,
            command.device_id,
            command.user_id,
        )
        .await
        .map_err(|e| e.map_to(
            || VerifyPopError::Unauthorized,
            || VerifyPopError::DeviceRevoked,
            VerifyPopError::DeviceRepository,
        ))?;

        // Build signature message using protocol format
        let signature_message =
            build_pop_signature_message(&command.challenge_str, &command.device_id_str)
                .map_err(|e| VerifyPopError::Internal(e.to_string()))?;

        // Verify Ed25519 signature
        crate::util::signature_verification::verify_ed25519_signature(
            &device.signing_public_key,
            &command.signature_bytes,
            &signature_message,
        )
        .map_err(|_| VerifyPopError::InvalidSignature)?;

        // Atomically verify and consume the challenge (GETDEL for one-time use)
        self.challenge_store
            .verify_and_remove(command.device_id, &command.challenge_bytes)
            .await
            .map_err(|e| match e {
                ChallengeError::NotFound => VerifyPopError::ChallengeNotFound,
                ChallengeError::Expired => VerifyPopError::ChallengeExpired,
                ChallengeError::StoreError => {
                    VerifyPopError::Internal("challenge store error".into())
                }
            })?;

        Ok(device.into())
    }
}
