//! Submit Trust State Command
//!
//! Existing device submits encrypted trust state for a new device.
//! Requires PoP verification for the sender device.

use chrono::{Duration, Utc};
use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{
    EncryptedTransferState, TransferNonceError, TransferNonceStore, TransferStateError,
    TransferStateStore,
};
use std::sync::Arc;
use thiserror::Error;

/// Submit state command
#[derive(Debug)]
pub struct SubmitStateCommand {
    /// User ID
    pub user_id: UserId,
    /// Sender device ID (existing device)
    pub sender_device_id: DeviceId,
    /// Target device ID (new device)
    pub target_device_id: DeviceId,
    /// Transfer nonce from the target device
    pub transfer_nonce: [u8; 32],
    /// Encrypted trust state
    pub encrypted_state: EncryptedTransferState,
}

/// Submit state error
#[derive(Debug, Error)]
pub enum SubmitStateError {
    #[error("invalid transfer nonce")]
    InvalidNonce,

    #[error("transfer nonce expired")]
    NonceExpired,

    #[error("state store error")]
    StoreError,
}

impl SubmitStateError {
    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            SubmitStateError::InvalidNonce | SubmitStateError::NonceExpired
        )
    }
}

impl From<TransferNonceError> for SubmitStateError {
    fn from(e: TransferNonceError) -> Self {
        match e {
            TransferNonceError::NotFound => SubmitStateError::InvalidNonce,
            TransferNonceError::Expired => SubmitStateError::NonceExpired,
            TransferNonceError::StoreError => SubmitStateError::StoreError,
        }
    }
}

impl From<TransferStateError> for SubmitStateError {
    fn from(e: TransferStateError) -> Self {
        match e {
            TransferStateError::NotFound => SubmitStateError::StoreError, // Shouldn't happen on store
            TransferStateError::StoreError => SubmitStateError::StoreError,
        }
    }
}

/// Submit state handler
pub struct SubmitStateHandler {
    nonce_store: Arc<dyn TransferNonceStore>,
    state_store: Arc<dyn TransferStateStore>,
}

impl SubmitStateHandler {
    pub fn new(
        nonce_store: Arc<dyn TransferNonceStore>,
        state_store: Arc<dyn TransferStateStore>,
    ) -> Self {
        Self {
            nonce_store,
            state_store,
        }
    }

    pub async fn handle(&self, command: SubmitStateCommand) -> Result<(), SubmitStateError> {
        // Verify and consume the nonce (prevents replay attacks)
        self.nonce_store
            .verify_and_consume(
                command.user_id,
                command.target_device_id,
                &command.transfer_nonce,
            )
            .await?;

        // Store the encrypted state (5 minute TTL)
        let expires_at = Utc::now() + Duration::minutes(5);
        self.state_store
            .store(
                command.user_id,
                command.target_device_id,
                command.encrypted_state,
                expires_at,
            )
            .await?;

        Ok(())
    }
}
