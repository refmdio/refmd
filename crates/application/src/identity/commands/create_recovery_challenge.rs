//! Recovery Challenge Creation Command
//!
//! Creates a server-issued challenge for account recovery.
//! The challenge must be signed with the user's Identity signing key
//! to create a recovery session.

use chrono::{Duration, Utc};
use domain::identity::{Email, EmailError};
use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
use std::sync::Arc;
use thiserror::Error;

/// Recovery challenge TTL in seconds (5 minutes)
const RECOVERY_CHALLENGE_TTL_SECS: i64 = 300;

/// Create recovery challenge command
#[derive(Debug)]
pub struct CreateRecoveryChallengeCommand {
    /// User email address (raw, will be normalized)
    pub email: String,
}

/// Create recovery challenge result
#[derive(Debug)]
pub struct CreateRecoveryChallengeResult {
    /// Generated 32-byte challenge
    pub challenge: [u8; 32],
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<Utc>,
}

/// Create recovery challenge error
#[derive(Debug, Error)]
pub enum CreateRecoveryChallengeError {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("failed to generate challenge")]
    RandomGeneration,

    #[error("failed to store challenge")]
    StoreError,
}

impl crate::types::AppError for CreateRecoveryChallengeError {
    fn is_invalid_input(&self) -> bool {
        matches!(self, CreateRecoveryChallengeError::InvalidEmail(_))
    }
}

impl From<RecoveryChallengeError> for CreateRecoveryChallengeError {
    fn from(_: RecoveryChallengeError) -> Self {
        CreateRecoveryChallengeError::StoreError
    }
}

/// Create recovery challenge handler
pub struct CreateRecoveryChallengeHandler {
    recovery_challenge_store: Arc<dyn RecoveryChallengeStore>,
}

impl CreateRecoveryChallengeHandler {
    pub fn new(recovery_challenge_store: Arc<dyn RecoveryChallengeStore>) -> Self {
        Self {
            recovery_challenge_store,
        }
    }

    pub async fn handle(
        &self,
        command: CreateRecoveryChallengeCommand,
    ) -> Result<CreateRecoveryChallengeResult, CreateRecoveryChallengeError> {
        // Validate and normalize email using domain type
        let email = Email::new(command.email)?;

        // Generate random 32-byte challenge using CSPRNG
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge)
            .map_err(|_| CreateRecoveryChallengeError::RandomGeneration)?;

        let expires_at = Utc::now() + Duration::seconds(RECOVERY_CHALLENGE_TTL_SECS);

        // Store challenge (always succeeds even for non-existent users — anti-enumeration)
        self.recovery_challenge_store
            .store(email.as_str(), challenge, expires_at)
            .await?;

        Ok(CreateRecoveryChallengeResult {
            challenge,
            expires_at,
        })
    }
}
