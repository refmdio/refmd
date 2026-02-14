//! Submit Trust State Command
//!
//! Existing device submits encrypted trust state for a new device.
//! Requires PoP verification for the sender device.

use chrono::{Duration, Utc};
use domain::encryption::{DeviceId, DeviceRepository, PendingDeviceRepository};
use domain::identity::UserId;
use domain::transfer_nonce::{
    TransferNonceError, TransferNonceStore, TransferStateError, TransferStateStore,
};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::EncryptedTransferStateDto;

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
    pub encrypted_state: EncryptedTransferStateDto,
}

/// Maximum size for encrypted state payload (1 MB)
const MAX_ENCRYPTED_STATE_SIZE: usize = 1024 * 1024;

/// Submit state error
#[derive(Debug, Error)]
pub enum SubmitStateError {
    #[error("invalid transfer nonce")]
    InvalidNonce,

    #[error("transfer nonce expired")]
    NonceExpired,

    #[error("target device not found or does not belong to user")]
    TargetDeviceNotFound,

    #[error("sender device ID mismatch between command and encrypted state")]
    SenderDeviceIdMismatch,

    #[error("encrypted state payload too large")]
    PayloadTooLarge,

    #[error("state store error")]
    StoreError,
}

impl crate::types::AppError for SubmitStateError {
    fn is_invalid_input(&self) -> bool {
        matches!(
            self,
            SubmitStateError::InvalidNonce
                | SubmitStateError::NonceExpired
                | SubmitStateError::TargetDeviceNotFound
                | SubmitStateError::SenderDeviceIdMismatch
        )
    }
}

/// Preserves error granularity for `submit_state` because the caller needs
/// to distinguish invalid/expired nonces (client error) from store failures
/// (server error) to return appropriate HTTP status codes and error codes.
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
pub struct SubmitStateHandler<DR: ?Sized, PDR: ?Sized> {
    nonce_store: Arc<dyn TransferNonceStore>,
    state_store: Arc<dyn TransferStateStore>,
    device_repo: Arc<DR>,
    pending_device_repo: Arc<PDR>,
}

impl<DR: ?Sized, PDR: ?Sized> SubmitStateHandler<DR, PDR>
where
    DR: DeviceRepository,
    PDR: PendingDeviceRepository,
{
    pub fn new(
        nonce_store: Arc<dyn TransferNonceStore>,
        state_store: Arc<dyn TransferStateStore>,
        device_repo: Arc<DR>,
        pending_device_repo: Arc<PDR>,
    ) -> Self {
        Self {
            nonce_store,
            state_store,
            device_repo,
            pending_device_repo,
        }
    }

    pub async fn handle(&self, command: SubmitStateCommand) -> Result<(), SubmitStateError> {
        // Check payload size limit
        if command.encrypted_state.ciphertext.len() > MAX_ENCRYPTED_STATE_SIZE {
            return Err(SubmitStateError::PayloadTooLarge);
        }

        // Defense-in-depth: verify sender_device_id consistency between command and
        // encrypted_state. The current HTTP handler always sets both from PoP-verified
        // device ID, but this guard protects against future callers constructing the
        // command incorrectly.
        if command.sender_device_id != command.encrypted_state.sender_device_id {
            return Err(SubmitStateError::SenderDeviceIdMismatch);
        }

        // Verify target device exists and belongs to this user (pending or active)
        use crate::util::device_ownership::{DeviceOwnershipError, check_device_ownership};
        check_device_ownership(
            &self.device_repo,
            &self.pending_device_repo,
            command.target_device_id,
            command.user_id,
        )
        .await
        .map_err(|e| match e {
            DeviceOwnershipError::NotFound => SubmitStateError::TargetDeviceNotFound,
            DeviceOwnershipError::PendingDeviceRepository(_)
            | DeviceOwnershipError::DeviceRepository(_) => SubmitStateError::StoreError,
        })?;

        // Verify and consume the nonce (prevents replay attacks)
        self.nonce_store
            .verify_and_consume(
                command.user_id,
                command.target_device_id,
                &command.transfer_nonce,
            )
            .await?;

        // Convert DTO to domain type and store (5 minute TTL)
        let domain_state = command.encrypted_state.into();
        let expires_at = Utc::now() + Duration::minutes(5);
        self.state_store
            .store(
                command.user_id,
                command.target_device_id,
                domain_state,
                expires_at,
            )
            .await?;

        Ok(())
    }
}
