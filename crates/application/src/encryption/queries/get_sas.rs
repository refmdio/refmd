//! Get SAS query
//!
//! Returns device public keys for client-side SAS calculation.
//! Both the existing device and the new device calculate SAS locally for MITM protection.

use crate::events::DeviceEventPublisher;
use domain::encryption::{DeviceId, PendingDeviceRepository};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// Get SAS query
#[derive(Debug)]
pub struct GetSasQuery {
    /// ID of the pending device
    pub pending_device_id: DeviceId,
    /// User ID (for ownership validation)
    pub user_id: UserId,
}

/// Get SAS result - returns device public keys for client-side SAS calculation
#[derive(Debug)]
pub struct GetSasResult {
    /// Device name
    pub device_name: String,
    /// Device type as string
    pub device_type: String,
    /// Pending device expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// New device's signing public key (32 bytes) - for client-side SAS calculation
    pub device_signing_public_key: Vec<u8>,
    /// New device's ECDH public key (32 bytes) - for client-side SAS calculation
    pub device_ecdh_public_key: Vec<u8>,
    /// Client nonce (16 bytes) - for client-side SAS calculation
    pub client_nonce: Vec<u8>,
}

/// Get SAS error
#[derive(Debug, Error)]
pub enum GetSasError<PDR: std::error::Error> {
    #[error("pending device not found")]
    PendingDeviceNotFound,

    #[error("pending device has expired")]
    PendingDeviceExpired,

    #[error("pending device does not belong to this user")]
    NotOwner,

    #[error("pending device repository error: {0}")]
    PendingDeviceRepository(PDR),
}

crate::types::impl_app_error!(
    [PDR: std::error::Error]
    GetSasError<PDR>,
    not_found: [GetSasError::PendingDeviceNotFound],
    access_denied: [GetSasError::NotOwner],
    gone: [GetSasError::PendingDeviceExpired],
);

/// Get SAS handler
pub struct GetSasHandler<PDR: ?Sized> {
    pending_device_repo: Arc<PDR>,
    event_publisher: Arc<dyn DeviceEventPublisher>,
}

impl<PDR> GetSasHandler<PDR>
where
    PDR: PendingDeviceRepository + ?Sized,
{
    pub fn new(
        pending_device_repo: Arc<PDR>,
        event_publisher: Arc<dyn DeviceEventPublisher>,
    ) -> Self {
        Self {
            pending_device_repo,
            event_publisher,
        }
    }

    pub async fn handle(
        &self,
        query: GetSasQuery,
    ) -> Result<GetSasResult, GetSasError<PDR::Error>> {
        // Find pending device
        let pending_device = self
            .pending_device_repo
            .find_by_id(query.pending_device_id)
            .await
            .map_err(GetSasError::PendingDeviceRepository)?
            .ok_or(GetSasError::PendingDeviceNotFound)?;

        // Verify ownership
        if pending_device.user_id != query.user_id {
            return Err(GetSasError::NotOwner);
        }

        // Check expiration — delete expired device before returning error
        if pending_device.is_expired() {
            if let Err(e) = self
                .pending_device_repo
                .delete(query.pending_device_id)
                .await
            {
                tracing::error!("failed to delete expired pending device: {}", e);
            }
            // Notify SSE listeners about the expiration
            self.event_publisher
                .pending_expired(query.pending_device_id, query.user_id)
                .await;
            return Err(GetSasError::PendingDeviceExpired);
        }

        // Return device public keys for client-side SAS calculation
        Ok(GetSasResult {
            device_name: pending_device.name.clone(),
            device_type: pending_device.device_type.as_str().to_string(),
            expires_at: pending_device.expires_at,
            device_signing_public_key: pending_device.signing_public_key.clone(),
            device_ecdh_public_key: pending_device.ecdh_public_key.clone(),
            client_nonce: pending_device.client_nonce.clone(),
        })
    }
}
