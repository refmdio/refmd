//! Get current user query handler
//!
//! Returns user info and encrypted keys for session restoration.

use std::sync::Arc;
use domain::encryption::{
    UserEncryptedIdentityKey, UserEncryptedIdentityKeyRepository, UserEncryptedMasterKey,
    UserEncryptedMasterKeyRepository,
};
use domain::identity::{Session, SessionRepository, User, UserRepository};
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
}

/// Get current user error
#[derive(Debug, Error)]
pub enum GetCurrentUserError<UR: std::error::Error, SR: std::error::Error, UEM: std::error::Error, UEI: std::error::Error> {
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
}

impl<UR, SR, UEM, UEI> GetCurrentUserError<UR, SR, UEM, UEI>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
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
pub struct GetCurrentUserHandler<U, S, UEM, UEI> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
}

impl<U, S, UEM, UEI> GetCurrentUserHandler<U, S, UEM, UEI>
where
    U: UserRepository,
    S: SessionRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        session_repo: Arc<S>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            encrypted_master_key_repo,
            encrypted_identity_key_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetCurrentUserQuery,
    ) -> Result<GetCurrentUserResult, GetCurrentUserError<U::Error, S::Error, UEM::Error, UEI::Error>>
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

        Ok(GetCurrentUserResult {
            user,
            session,
            encrypted_master_key,
            encrypted_identity_key,
        })
    }
}
