//! Request Transfer Nonce Command
//!
//! New device requests a nonce for trust state transfer.
//! The nonce is used for replay protection.

use crate::events::DeviceEventPublisher;
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
    #[error("device repository error")]
    DeviceRepository,
    #[error("pending device repository error")]
    PendingDeviceRepository,
}

impl crate::types::AppError for RequestNonceError {
    fn is_not_found(&self) -> bool {
        matches!(self, RequestNonceError::DeviceNotFound)
    }
}

/// All `TransferNonceError` variants collapse to `StoreError` because
/// nonce generation should never encounter NotFound/Expired — those are
/// internal store errors at this stage. Keeping a single variant simplifies
/// the handler's error surface.
impl From<TransferNonceError> for RequestNonceError {
    fn from(e: TransferNonceError) -> Self {
        match e {
            TransferNonceError::NotFound
            | TransferNonceError::Expired
            | TransferNonceError::StoreError => RequestNonceError::StoreError,
        }
    }
}

/// Request nonce handler
pub struct RequestNonceHandler<DR: ?Sized, PDR: ?Sized> {
    nonce_store: Arc<dyn TransferNonceStore>,
    device_repo: Arc<DR>,
    pending_device_repo: Arc<PDR>,
    event_publisher: Arc<dyn DeviceEventPublisher>,
}

impl<DR: ?Sized, PDR: ?Sized> RequestNonceHandler<DR, PDR>
where
    DR: DeviceRepository,
    PDR: PendingDeviceRepository,
{
    pub fn new(
        nonce_store: Arc<dyn TransferNonceStore>,
        device_repo: Arc<DR>,
        pending_device_repo: Arc<PDR>,
        event_publisher: Arc<dyn DeviceEventPublisher>,
    ) -> Self {
        Self {
            nonce_store,
            device_repo,
            pending_device_repo,
            event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: RequestNonceCommand,
    ) -> Result<RequestNonceResult, RequestNonceError> {
        // Verify device exists and belongs to the user (pending or active)
        use crate::util::device_ownership::{DeviceOwnershipError, check_device_ownership};
        check_device_ownership(
            &self.device_repo,
            &self.pending_device_repo,
            command.new_device_id,
            command.user_id,
        )
        .await
        .map_err(|e| match e {
            DeviceOwnershipError::NotFound => RequestNonceError::DeviceNotFound,
            DeviceOwnershipError::PendingDeviceRepository(_) => {
                RequestNonceError::PendingDeviceRepository
            }
            DeviceOwnershipError::DeviceRepository(_) => RequestNonceError::DeviceRepository,
        })?;

        // Generate random nonce
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| RequestNonceError::StoreError)?;

        // Set expiration (5 minutes)
        let expires_at = Utc::now() + Duration::minutes(5);

        // Store nonce
        self.nonce_store
            .store(command.user_id, command.new_device_id, nonce, expires_at)
            .await?;

        // Notify existing devices about the transfer nonce
        self.event_publisher
            .trust_transfer_nonce_ready(command.user_id, command.new_device_id, &nonce)
            .await;

        Ok(RequestNonceResult { nonce, expires_at })
    }
}
