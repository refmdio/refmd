//! Get recovery data query handler
//!
//! Returns encrypted UMK (recovery-encrypted) for account recovery.
//! Also returns encrypted identity keys so user can fully restore access.

use domain::encryption::{UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository};
use domain::identity::{Email, EmailError, UserRepository};
use std::sync::Arc;
use thiserror::Error;

/// Get recovery data query
#[derive(Debug)]
pub struct GetRecoveryDataQuery {
    pub email: String,
}

/// Get recovery data result
#[derive(Debug)]
pub struct GetRecoveryDataResult {
    /// User ID (needed for AAD verification on client)
    pub user_id: uuid::Uuid,
    /// UMK encrypted with recovery key (RUK)
    pub recovery_encrypted_umk: Vec<u8>,
    /// Nonce for recovery encryption
    pub recovery_nonce: Vec<u8>,
    /// Encrypted ECDH private key (with UMK)
    pub encrypted_ecdh_private: Vec<u8>,
    /// Nonce for ECDH private key encryption
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    /// Encrypted signing private key (with UMK)
    pub encrypted_signing_private: Vec<u8>,
    /// Nonce for signing private key encryption
    pub encrypted_signing_private_nonce: Vec<u8>,
}

/// Get recovery data error
#[derive(Debug, Error)]
pub enum GetRecoveryDataError<UR: std::error::Error, UEM: std::error::Error, UEI: std::error::Error>
{
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("user not found")]
    UserNotFound,

    #[error("recovery data not available")]
    RecoveryDataNotAvailable,

    #[error("identity keys not found")]
    IdentityKeysNotFound,

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("encrypted master key repository error: {0}")]
    EncryptedMasterKeyRepository(UEM),

    #[error("encrypted identity key repository error: {0}")]
    EncryptedIdentityKeyRepository(UEI),
}

impl<UR, UEM, UEI> GetRecoveryDataError<UR, UEM, UEI>
where
    UR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
{
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetRecoveryDataError::UserNotFound
                | GetRecoveryDataError::RecoveryDataNotAvailable
                | GetRecoveryDataError::IdentityKeysNotFound
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, GetRecoveryDataError::InvalidEmail(_))
    }
}

/// Get recovery data handler
pub struct GetRecoveryDataHandler<U, UEM, UEI> {
    user_repo: Arc<U>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
}

impl<U, UEM, UEI> GetRecoveryDataHandler<U, UEM, UEI>
where
    U: UserRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
    ) -> Self {
        Self {
            user_repo,
            encrypted_master_key_repo,
            encrypted_identity_key_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetRecoveryDataQuery,
    ) -> Result<GetRecoveryDataResult, GetRecoveryDataError<U::Error, UEM::Error, UEI::Error>> {
        // Validate email format
        let email = Email::new(&query.email)?;

        // Find user by email
        let user = self
            .user_repo
            .find_by_email(&email)
            .await
            .map_err(GetRecoveryDataError::UserRepository)?
            .ok_or(GetRecoveryDataError::UserNotFound)?;

        // Get encrypted master key (for recovery data)
        let umk = self
            .encrypted_master_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(GetRecoveryDataError::EncryptedMasterKeyRepository)?
            .ok_or(GetRecoveryDataError::RecoveryDataNotAvailable)?;

        // Verify recovery data exists
        if umk.recovery_encrypted_umk.is_empty() || umk.recovery_nonce.is_empty() {
            return Err(GetRecoveryDataError::RecoveryDataNotAvailable);
        }

        // Get encrypted identity keys
        let identity_keys = self
            .encrypted_identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(GetRecoveryDataError::EncryptedIdentityKeyRepository)?
            .ok_or(GetRecoveryDataError::IdentityKeysNotFound)?;

        Ok(GetRecoveryDataResult {
            user_id: user.id.as_uuid(),
            recovery_encrypted_umk: umk.recovery_encrypted_umk,
            recovery_nonce: umk.recovery_nonce,
            encrypted_ecdh_private: identity_keys.encrypted_ecdh_private,
            encrypted_ecdh_private_nonce: identity_keys.encrypted_ecdh_private_nonce,
            encrypted_signing_private: identity_keys.encrypted_signing_private,
            encrypted_signing_private_nonce: identity_keys.encrypted_signing_private_nonce,
        })
    }
}
