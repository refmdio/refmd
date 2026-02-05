//! Request Transfer Nonce Command
//!
//! New device requests a nonce for trust state transfer.
//! The nonce is used for replay protection.

use chrono::{Duration, Utc};
use domain::encryption::{DeviceId, DeviceRepository, PendingDeviceRepository};
use domain::identity::UserId;
use domain::transfer_nonce::{TransferNonceError, TransferNonceStore};
use std::sync::Arc;
use thiserror::Error;

/// Request nonce command
#[derive(Debug)]
pub struct RequestNonceCommand {
    /// User ID
    pub user_id: UserId,
    /// New device ID requesting the transfer
    pub new_device_id: DeviceId,
}

/// Request nonce result
#[derive(Debug)]
pub struct RequestNonceResult {
    /// Generated nonce (32 bytes)
    pub nonce: [u8; 32],
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<Utc>,
}

/// Request nonce error
#[derive(Debug, Error)]
pub enum RequestNonceError {
    #[error("device not found")]
    DeviceNotFound,
    #[error("nonce store error")]
    StoreError,
}

impl RequestNonceError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, RequestNonceError::DeviceNotFound)
    }
}

impl From<TransferNonceError> for RequestNonceError {
    fn from(e: TransferNonceError) -> Self {
        match e {
            TransferNonceError::StoreError => RequestNonceError::StoreError,
            _ => RequestNonceError::StoreError,
        }
    }
}

/// Request nonce handler
pub struct RequestNonceHandler<DR, PDR> {
    nonce_store: Arc<dyn TransferNonceStore>,
    device_repo: Arc<DR>,
    pending_device_repo: Arc<PDR>,
}

impl<DR, PDR> RequestNonceHandler<DR, PDR>
where
    DR: DeviceRepository,
    PDR: PendingDeviceRepository,
{
    pub fn new(
        nonce_store: Arc<dyn TransferNonceStore>,
        device_repo: Arc<DR>,
        pending_device_repo: Arc<PDR>,
    ) -> Self {
        Self {
            nonce_store,
            device_repo,
            pending_device_repo,
        }
    }

    pub async fn handle(
        &self,
        command: RequestNonceCommand,
    ) -> Result<RequestNonceResult, RequestNonceError> {
        // Verify device exists and belongs to the user (pending or active)
        let is_pending = match self.pending_device_repo.find_by_id(command.new_device_id).await {
            Ok(Some(pending)) => pending.user_id == command.user_id,
            _ => false,
        };

        let is_active = match self.device_repo.find_by_id(command.new_device_id).await {
            Ok(Some(device)) => device.user_id == command.user_id && !device.is_revoked(),
            _ => false,
        };

        if !is_pending && !is_active {
            return Err(RequestNonceError::DeviceNotFound);
        }

        // Generate random nonce
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| RequestNonceError::StoreError)?;

        // Set expiration (5 minutes)
        let expires_at = Utc::now() + Duration::minutes(5);

        // Store nonce
        self.nonce_store
            .store(command.user_id, command.new_device_id, nonce, expires_at)
            .await?;

        Ok(RequestNonceResult { nonce, expires_at })
    }
}
