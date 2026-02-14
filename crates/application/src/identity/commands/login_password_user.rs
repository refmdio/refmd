//! Login password user command
//!
//! Authenticates a password-based user and creates a session.

use domain::encryption::{
    DeviceId, DeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository,
};
use domain::identity::{Email, EmailError, Session, SessionRepository, UserRepository};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::UserDto;

/// Valid bcrypt hash generated once at startup for timing attack mitigation.
/// `bcrypt::verify` is called against this hash on every authentication
/// failure path so that response time is indistinguishable from the
/// success path, preventing user-enumeration via timing.
static DUMMY_BCRYPT_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    bcrypt::hash("__timing_attack_mitigation__", 12)
        .expect("failed to generate dummy bcrypt hash for timing mitigation")
});

/// Consume CPU time equivalent to a real bcrypt verify.
/// Called on every authentication failure path to prevent
/// user-enumeration via response timing.
fn consume_dummy_bcrypt(auth_key: &str) {
    let _ = bcrypt::verify(auth_key, &DUMMY_BCRYPT_HASH);
}

/// Login password user command
#[derive(Debug)]
pub struct LoginPasswordUserCommand {
    pub email: String,
    /// authKey (base64url encoded string)
    pub auth_key: String,
    pub remember_me: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Device ID for session binding (for is_current detection)
    pub device_id: Option<DeviceId>,
}

/// Login password user result
#[derive(Debug)]
pub struct LoginPasswordUserResult {
    pub user: UserDto,
    pub session_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether user has any registered devices (for PoP enforcement)
    pub has_devices: bool,
    /// Whether the login device is verified (registered and active)
    pub device_verified: bool,
    /// Device ID if verified
    pub device_id: Option<DeviceId>,
    /// Encrypted keys - only present if device is verified
    /// This prevents new/unverified devices from receiving UMK
    pub keys: Option<LoginKeys>,
}

/// Encrypted keys returned only for verified devices
#[derive(Debug)]
pub struct LoginKeys {
    /// Encrypted UMK (for client to decrypt with PUK)
    pub encrypted_umk: Vec<u8>,
    pub umk_nonce: Vec<u8>,
    /// Encrypted identity keys
    pub encrypted_ecdh_private: Vec<u8>,
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    pub encrypted_signing_private: Vec<u8>,
    pub encrypted_signing_private_nonce: Vec<u8>,
}

/// Login password user error
#[derive(Debug, Error)]
pub enum LoginPasswordUserError<
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DR: std::error::Error,
> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user is not a password user")]
    NotPasswordUser,

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
    DeviceRepository(DR),

    #[error("random number generator error: {0}")]
    Rng(getrandom::Error),
}

impl<UR, SR, UEM, UEI, DR> crate::types::AppError for LoginPasswordUserError<UR, SR, UEM, UEI, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DR: std::error::Error,
{
    fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            LoginPasswordUserError::InvalidCredentials | LoginPasswordUserError::NotPasswordUser
        )
    }

    fn is_invalid_input(&self) -> bool {
        matches!(self, LoginPasswordUserError::InvalidEmail(_))
    }
}

impl<UR, SR, UEM, UEI, DR> crate::types::SafeMessage for LoginPasswordUserError<UR, SR, UEM, UEI, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DR: std::error::Error,
{
    /// Convert to a safe error message that doesn't leak user information.
    /// This prevents user enumeration attacks.
    ///
    /// Error categorization:
    /// - `InvalidEmail`: HTTP 400 - Format error, safe to show "invalid email"
    ///   (doesn't reveal user existence as it fails before DB lookup)
    /// - `InvalidCredentials`/`NotPasswordUser`: HTTP 401 - Always "invalid credentials"
    ///   (unified message prevents user enumeration)
    /// - `DataInconsistency` and repo errors: HTTP 500 - "internal server error"
    fn safe_message(&self) -> &'static str {
        match self {
            // Format error - safe to be specific (HTTP 400)
            LoginPasswordUserError::InvalidEmail(_) => "invalid email",
            // All authentication failures return the same message (HTTP 401)
            LoginPasswordUserError::InvalidCredentials
            | LoginPasswordUserError::NotPasswordUser => "invalid credentials",
            // Internal errors (HTTP 500)
            LoginPasswordUserError::DataInconsistency
            | LoginPasswordUserError::UserRepository(_)
            | LoginPasswordUserError::SessionRepository(_)
            | LoginPasswordUserError::EncryptedMasterKeyRepository(_)
            | LoginPasswordUserError::EncryptedIdentityKeyRepository(_)
            | LoginPasswordUserError::DeviceRepository(_)
            | LoginPasswordUserError::Rng(_) => "internal server error",
        }
    }
}

/// Login password user handler
pub struct LoginPasswordUserHandler<U: ?Sized, S: ?Sized, UEM: ?Sized, UEI: ?Sized, DR: ?Sized> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    device_repo: Arc<DR>,
}

impl<U: ?Sized, S: ?Sized, UEM: ?Sized, UEI: ?Sized, DR: ?Sized> LoginPasswordUserHandler<U, S, UEM, UEI, DR>
where
    U: UserRepository,
    S: SessionRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
    DR: DeviceRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        session_repo: Arc<S>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
        device_repo: Arc<DR>,
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
        command: LoginPasswordUserCommand,
    ) -> Result<
        LoginPasswordUserResult,
        LoginPasswordUserError<U::Error, S::Error, UEM::Error, UEI::Error, DR::Error>,
    > {
        // Phase 1: Validate email format (HTTP 400, no timing concern)
        let email = Email::new(&command.email)?;

        // Phase 2: Authenticate credentials (constant-time via dummy bcrypt)
        let (user, encrypted_master_key, encrypted_identity_key) =
            self.authenticate(&email, &command.auth_key).await?;

        // Phase 3: Validate encryption keys exist
        let encrypted_umk = encrypted_master_key
            .encrypted_umk
            .ok_or(LoginPasswordUserError::DataInconsistency)?;
        let umk_nonce = encrypted_master_key
            .umk_nonce
            .ok_or(LoginPasswordUserError::DataInconsistency)?;

        // Phase 4: Create session with validated device binding
        let device_check = crate::util::device_ownership::verify_session_device(
            &self.device_repo,
            user.id,
            command.device_id,
        )
        .await
        .map_err(LoginPasswordUserError::DeviceRepository)?;

        let session_token =
            generate_session_token().map_err(LoginPasswordUserError::Rng)?;
        let token_hash = hash_session_token(&session_token);
        let session = Session::with_device(
            user.id,
            device_check.verified_device_id,
            token_hash,
            command.remember_me,
            command.ip_address,
            command.user_agent,
        );
        self.session_repo
            .save(&session)
            .await
            .map_err(LoginPasswordUserError::SessionRepository)?;

        // Phase 5: Build result with keys only for verified devices
        let keys = if device_check.device_verified {
            Some(LoginKeys {
                encrypted_umk,
                umk_nonce,
                encrypted_ecdh_private: encrypted_identity_key.encrypted_ecdh_private,
                encrypted_ecdh_private_nonce: encrypted_identity_key.encrypted_ecdh_private_nonce,
                encrypted_signing_private: encrypted_identity_key.encrypted_signing_private,
                encrypted_signing_private_nonce: encrypted_identity_key
                    .encrypted_signing_private_nonce,
            })
        } else {
            None
        };

        Ok(LoginPasswordUserResult {
            user: user.into(),
            session_token,
            expires_at: session.expires_at,
            has_devices: device_check.has_devices,
            device_verified: device_check.device_verified,
            device_id: device_check.verified_device_id,
            keys,
        })
    }

    /// Authenticate user credentials with constant-time behaviour.
    ///
    /// On every failure path a dummy bcrypt verification runs to prevent
    /// user enumeration via response timing.
    async fn authenticate(
        &self,
        email: &Email,
        auth_key: &str,
    ) -> Result<
        (
            domain::identity::User,
            domain::encryption::UserEncryptedMasterKey,
            domain::encryption::UserEncryptedIdentityKey,
        ),
        LoginPasswordUserError<U::Error, S::Error, UEM::Error, UEI::Error, DR::Error>,
    > {
        let user = match self
            .user_repo
            .find_by_email(email)
            .await
            .map_err(LoginPasswordUserError::UserRepository)?
        {
            Some(u) => u,
            None => {
                consume_dummy_bcrypt(auth_key);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        let emk = match self
            .encrypted_master_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(LoginPasswordUserError::EncryptedMasterKeyRepository)?
        {
            Some(emk) => emk,
            None => {
                consume_dummy_bcrypt(auth_key);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        if !emk.is_password_user() {
            consume_dummy_bcrypt(auth_key);
            return Err(LoginPasswordUserError::NotPasswordUser);
        }

        let hash = match emk.auth_key_hash.as_ref() {
            Some(h) => h,
            None => {
                consume_dummy_bcrypt(auth_key);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        let is_valid = bcrypt::verify(auth_key, hash)
            .map_err(|_| LoginPasswordUserError::InvalidCredentials)?;
        if !is_valid {
            return Err(LoginPasswordUserError::InvalidCredentials);
        }

        let eik = self
            .encrypted_identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(LoginPasswordUserError::EncryptedIdentityKeyRepository)?
            .ok_or(LoginPasswordUserError::InvalidCredentials)?;

        Ok((user, emk, eik))
    }
}

use crate::identity::session_token::{generate_session_token, hash_session_token};
