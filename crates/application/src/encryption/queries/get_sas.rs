//! Get SAS query
//!
//! Retrieves the SAS (Short Authentication String) for a pending device.
//! Both the existing device and the new device use this to verify the connection.

use domain::encryption::{DeviceId, PendingDeviceRepository, UserIdentityPublicKeyRepository};
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

/// Get SAS result
#[derive(Debug)]
pub struct GetSasResult {
    /// SAS emoji indices (7 bytes, each 0-255) - computed server-side for reference
    pub sas_indices: Vec<u8>,
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
pub enum GetSasError<PDR: std::error::Error, UIPR: std::error::Error> {
    #[error("pending device not found")]
    PendingDeviceNotFound,

    #[error("pending device has expired")]
    PendingDeviceExpired,

    #[error("pending device does not belong to this user")]
    NotOwner,

    #[error("user identity public key not found")]
    IdentityKeyNotFound,

    #[error("pending device repository error: {0}")]
    PendingDeviceRepository(PDR),

    #[error("identity public key repository error: {0}")]
    IdentityPublicKeyRepository(UIPR),
}

impl<PDR: std::error::Error, UIPR: std::error::Error> GetSasError<PDR, UIPR> {
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetSasError::PendingDeviceNotFound | GetSasError::IdentityKeyNotFound
        )
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(self, GetSasError::NotOwner)
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, GetSasError::PendingDeviceExpired)
    }
}

/// Get SAS handler
pub struct GetSasHandler<PDR, UIPR> {
    pending_device_repo: Arc<PDR>,
    identity_public_key_repo: Arc<UIPR>,
}

impl<PDR, UIPR> GetSasHandler<PDR, UIPR>
where
    PDR: PendingDeviceRepository,
    UIPR: UserIdentityPublicKeyRepository,
{
    pub fn new(pending_device_repo: Arc<PDR>, identity_public_key_repo: Arc<UIPR>) -> Self {
        Self {
            pending_device_repo,
            identity_public_key_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetSasQuery,
    ) -> Result<GetSasResult, GetSasError<PDR::Error, UIPR::Error>> {
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

        // Check expiration
        if pending_device.is_expired() {
            return Err(GetSasError::PendingDeviceExpired);
        }

        // Get user's identity public key for SAS generation
        let identity_key = self
            .identity_public_key_repo
            .find_by_user_id(query.user_id)
            .await
            .map_err(GetSasError::IdentityPublicKeyRepository)?
            .ok_or(GetSasError::IdentityKeyNotFound)?;

        // Generate SAS indices using BLAKE3
        let sas_indices = generate_sas_indices(
            &identity_key.signing_public_key,
            &pending_device.signing_public_key,
            &pending_device.ecdh_public_key,
            &pending_device.client_nonce,
        );

        Ok(GetSasResult {
            sas_indices,
            device_name: pending_device.name.clone(),
            device_type: pending_device.device_type.as_str().to_string(),
            expires_at: pending_device.expires_at,
            device_signing_public_key: pending_device.signing_public_key.clone(),
            device_ecdh_public_key: pending_device.ecdh_public_key.clone(),
            client_nonce: pending_device.client_nonce.clone(),
        })
    }
}

/// Generate SAS indices from public keys and nonce
fn generate_sas_indices(
    identity_signing_pk: &[u8],
    device_signing_pk: &[u8],
    device_ecdh_pk: &[u8],
    client_nonce: &[u8],
) -> Vec<u8> {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(identity_signing_pk);
    hasher.update(device_signing_pk);
    hasher.update(device_ecdh_pk);
    hasher.update(client_nonce);

    let hash = hasher.finalize();
    hash.as_bytes()[..7].to_vec()
}
