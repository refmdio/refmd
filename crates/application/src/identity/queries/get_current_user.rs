//! Get current user query handler
//!
//! Returns user info and encrypted keys for session restoration.

use domain::encryption::{
    DeviceId, DeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository,
};
use domain::identity::{SessionRepository, UserRepository};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::{SessionDto, UserDto};

/// Get current user query
#[derive(Debug)]
pub struct GetCurrentUserQuery {
    /// Session token hash (SHA-256 of the token)
    pub token_hash: String,
}

/// Get current user result
#[derive(Debug)]
pub struct GetCurrentUserResult {
    pub user: UserDto,
    pub session: SessionDto,
    /// "password" or "oauth"
    pub auth_type: String,
    /// Whether the session's device is verified (exists, active, belongs to user)
    pub device_verified: bool,
    /// The verified device ID (if device_verified is true)
    pub device_id: Option<DeviceId>,
    /// Whether the user has any active devices
    pub has_devices: bool,
    /// Encrypted keys — only present when device is verified.
    /// Application layer resolves password vs OAuth key invariants.
    pub keys: Option<MeKeys>,
}

/// Encrypted keys for the /me response, pre-resolved by application layer.
#[derive(Debug)]
pub struct MeKeys {
    /// Encrypted UMK (None for OAuth users who use DSK/recovery key)
    pub encrypted_umk: Option<Vec<u8>>,
    /// UMK nonce (None for OAuth users)
    pub umk_nonce: Option<Vec<u8>>,
    pub encrypted_ecdh_private: Vec<u8>,
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    pub encrypted_signing_private: Vec<u8>,
    pub encrypted_signing_private_nonce: Vec<u8>,
}

/// Get current user error
#[derive(Debug, Error)]
pub enum GetCurrentUserError<
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DER: std::error::Error,
> {
    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("user not found")]
    UserNotFound,

    #[error("encryption keys not found")]
    EncryptionKeysNotFound,

    #[error("data inconsistency: password user missing encryption keys")]
    DataInconsistency,

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("session repository error: {0}")]
    SessionRepository(SR),

    #[error("encrypted master key repository error: {0}")]
    EncryptedMasterKeyRepository(UEM),

    #[error("encrypted identity key repository error: {0}")]
    EncryptedIdentityKeyRepository(UEI),

    #[error("device repository error: {0}")]
    DeviceRepository(DER),
}

impl<UR, SR, UEM, UEI, DER> crate::types::AppError for GetCurrentUserError<UR, SR, UEM, UEI, DER>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DER: std::error::Error,
{
    fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            GetCurrentUserError::SessionNotFound
                | GetCurrentUserError::SessionExpired
                | GetCurrentUserError::UserNotFound
        )
    }
}

/// Get current user handler
pub struct GetCurrentUserHandler<U: ?Sized, S: ?Sized, UEM: ?Sized, UEI: ?Sized, DER: ?Sized> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    device_repo: Arc<DER>,
}

impl<U: ?Sized, S: ?Sized, UEM: ?Sized, UEI: ?Sized, DER: ?Sized> GetCurrentUserHandler<U, S, UEM, UEI, DER>
where
    U: UserRepository,
    S: SessionRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
    DER: DeviceRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        session_repo: Arc<S>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
        device_repo: Arc<DER>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            encrypted_master_key_repo,
            encrypted_identity_key_repo,
            device_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetCurrentUserQuery,
    ) -> Result<GetCurrentUserResult, GetCurrentUserError<U::Error, S::Error, UEM::Error, UEI::Error, DER::Error>>
    {
        // Find session by token hash
        let session = self
            .session_repo
            .find_by_token_hash(&query.token_hash)
            .await
            .map_err(GetCurrentUserError::SessionRepository)?
            .ok_or(GetCurrentUserError::SessionNotFound)?;

        // Check if session is expired
        if session.is_expired() {
            return Err(GetCurrentUserError::SessionExpired);
        }

        // Get user
        let user = self
            .user_repo
            .find_by_id(session.user_id)
            .await
            .map_err(GetCurrentUserError::UserRepository)?
            .ok_or(GetCurrentUserError::UserNotFound)?;

        // Get encrypted master key
        let encrypted_master_key = self
            .encrypted_master_key_repo
            .find_by_user_id(session.user_id)
            .await
            .map_err(GetCurrentUserError::EncryptedMasterKeyRepository)?
            .ok_or(GetCurrentUserError::EncryptionKeysNotFound)?;

        // Get encrypted identity keys
        let encrypted_identity_key = self
            .encrypted_identity_key_repo
            .find_by_user_id(session.user_id)
            .await
            .map_err(GetCurrentUserError::EncryptedIdentityKeyRepository)?
            .ok_or(GetCurrentUserError::EncryptionKeysNotFound)?;

        // Check device verification (shared utility with login handler)
        let device_check = crate::util::device_ownership::verify_session_device(
            &self.device_repo,
            session.user_id,
            session.device_id,
        )
        .await
        .map_err(GetCurrentUserError::DeviceRepository)?;
        let has_devices = device_check.has_devices;
        let device_verified = device_check.device_verified;
        let device_id = device_check.verified_device_id;

        // Determine auth type
        let is_password_user = encrypted_master_key.is_password_user();
        let auth_type = if is_password_user { "password" } else { "oauth" }.to_string();

        // Resolve keys only for verified devices
        let keys = if device_verified {
            // Resolve UMK: present for password users, None for OAuth
            let (encrypted_umk, umk_nonce) = match (&encrypted_master_key.encrypted_umk, &encrypted_master_key.umk_nonce) {
                (Some(enc), Some(nonce)) if !enc.is_empty() => (Some(enc.clone()), Some(nonce.clone())),
                _ => {
                    if is_password_user {
                        return Err(GetCurrentUserError::DataInconsistency);
                    }
                    (None, None)
                }
            };

            Some(MeKeys {
                encrypted_umk,
                umk_nonce,
                encrypted_ecdh_private: encrypted_identity_key.encrypted_ecdh_private,
                encrypted_ecdh_private_nonce: encrypted_identity_key.encrypted_ecdh_private_nonce,
                encrypted_signing_private: encrypted_identity_key.encrypted_signing_private,
                encrypted_signing_private_nonce: encrypted_identity_key.encrypted_signing_private_nonce,
            })
        } else {
            None
        };

        Ok(GetCurrentUserResult {
            user: user.into(),
            session: session.into(),
            auth_type,
            device_verified,
            device_id,
            has_devices,
            keys,
        })
    }
}
