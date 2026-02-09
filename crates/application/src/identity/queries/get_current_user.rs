//! Get current user query handler
//!
//! Returns user info and encrypted keys for session restoration.

use domain::encryption::{
    DeviceId, DeviceRepository, UserEncryptedIdentityKey, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKey, UserEncryptedMasterKeyRepository,
};
use domain::identity::{Session, SessionRepository, User, UserRepository};
use std::sync::Arc;
use thiserror::Error;

/// Get current user query
#[derive(Debug)]
pub struct GetCurrentUserQuery {
    /// Session token hash (SHA-256 of the token)
    pub token_hash: String,
}

/// Get current user result
#[derive(Debug)]
pub struct GetCurrentUserResult {
    pub user: User,
    pub session: Session,
    pub encrypted_master_key: UserEncryptedMasterKey,
    pub encrypted_identity_key: UserEncryptedIdentityKey,
    /// Whether the session's device is verified (exists, active, belongs to user)
    pub device_verified: bool,
    /// The verified device ID (if device_verified is true)
    pub device_id: Option<DeviceId>,
    /// Whether the user has any active devices
    pub has_devices: bool,
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

impl<UR, SR, UEM, UEI, DER> GetCurrentUserError<UR, SR, UEM, UEI, DER>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DER: std::error::Error,
{
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            GetCurrentUserError::SessionNotFound
                | GetCurrentUserError::SessionExpired
                | GetCurrentUserError::UserNotFound
        )
    }
}

/// Get current user handler
pub struct GetCurrentUserHandler<U, S, UEM, UEI, DER> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    device_repo: Arc<DER>,
}

impl<U, S, UEM, UEI, DER> GetCurrentUserHandler<U, S, UEM, UEI, DER>
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

        // Check device verification (same pattern as login handler)
        let devices = self
            .device_repo
            .find_active_by_user_id(session.user_id)
            .await
            .map_err(GetCurrentUserError::DeviceRepository)?;
        let has_devices = !devices.is_empty();

        let (device_verified, device_id) = if let Some(session_device_id) = session.device_id {
            let device_valid = devices.iter().any(|d| d.id == session_device_id);
            (
                device_valid,
                if device_valid {
                    Some(session_device_id)
                } else {
                    None
                },
            )
        } else {
            (false, None)
        };

        Ok(GetCurrentUserResult {
            user,
            session,
            encrypted_master_key,
            encrypted_identity_key,
            device_verified,
            device_id,
            has_devices,
        })
    }
}
