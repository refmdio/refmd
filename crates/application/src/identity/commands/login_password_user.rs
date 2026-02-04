//! Login password user command
//!
//! Authenticates a password-based user and creates a session.

use domain::encryption::{
    DeviceId, DeviceRepository, UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
};
use domain::identity::{Email, EmailError, Session, SessionRepository, User, UserRepository};
use std::sync::Arc;
use thiserror::Error;

/// Dummy bcrypt hash for timing attack mitigation.
/// This hash is verified when user doesn't exist to equalize response time
/// with valid user authentication attempts.
/// Valid bcrypt hash format (cost 12) - the actual value doesn't matter,
/// only that bcrypt::verify runs to consume similar CPU time as real verification.
const DUMMY_BCRYPT_HASH: &str = "$2b$12$K4IvyNEH/3tAJhJ5zDvYNuGXYbN5L0e5vNPVZxXXXXXXXXXXXXXXX";

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
    pub user: User,
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
}

impl<UR, SR, UEM, UEI, DR> LoginPasswordUserError<UR, SR, UEM, UEI, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    DR: std::error::Error,
{
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            LoginPasswordUserError::InvalidCredentials | LoginPasswordUserError::NotPasswordUser
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, LoginPasswordUserError::InvalidEmail(_))
    }

    /// Convert to a safe error message that doesn't leak user information.
    /// This prevents user enumeration attacks.
    ///
    /// Error categorization:
    /// - `InvalidEmail`: HTTP 400 - Format error, safe to show "invalid email"
    ///   (doesn't reveal user existence as it fails before DB lookup)
    /// - `InvalidCredentials`/`NotPasswordUser`: HTTP 401 - Always "invalid credentials"
    ///   (unified message prevents user enumeration)
    /// - `DataInconsistency` and repo errors: HTTP 500 - "internal server error"
    pub fn safe_message(&self) -> &'static str {
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
            | LoginPasswordUserError::DeviceRepository(_) => "internal server error",
        }
    }

    pub fn is_internal_error(&self) -> bool {
        matches!(self, LoginPasswordUserError::DataInconsistency)
    }
}

/// Login password user handler
pub struct LoginPasswordUserHandler<U, S, UEM, UEI, DR> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    device_repo: Arc<DR>,
}

impl<U, S, UEM, UEI, DR> LoginPasswordUserHandler<U, S, UEM, UEI, DR>
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
        // Validate and parse email
        // Note: InvalidEmail is returned as HTTP 400 (Bad Request), not 401 (Unauthorized).
        // This is intentional - email format validation is a syntactic check that happens
        // BEFORE any database lookup. It doesn't reveal user existence, so no timing
        // attack mitigation (dummy bcrypt) is needed here.
        let email = Email::new(&command.email)?;

        // Find user by email
        let user_result = self
            .user_repo
            .find_by_email(&email)
            .await
            .map_err(LoginPasswordUserError::UserRepository)?;

        // If user doesn't exist, run dummy bcrypt to prevent timing attacks
        // then return InvalidCredentials
        let user = match user_result {
            Some(u) => u,
            None => {
                // Run dummy bcrypt verification to equalize timing
                // This prevents attackers from detecting non-existent users via response time
                let _ = bcrypt::verify(&command.auth_key, DUMMY_BCRYPT_HASH);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        // Get encrypted master key (contains auth_key_hash)
        let encrypted_master_key = self
            .encrypted_master_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(LoginPasswordUserError::EncryptedMasterKeyRepository)?;

        // If no encrypted master key, run dummy bcrypt and return error
        let encrypted_master_key = match encrypted_master_key {
            Some(emk) => emk,
            None => {
                let _ = bcrypt::verify(&command.auth_key, DUMMY_BCRYPT_HASH);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        // Ensure this is a password user
        if !encrypted_master_key.is_password_user() {
            // Run dummy bcrypt to equalize timing with valid password verification
            let _ = bcrypt::verify(&command.auth_key, DUMMY_BCRYPT_HASH);
            return Err(LoginPasswordUserError::NotPasswordUser);
        }

        // Get auth_key_hash (should exist for password users)
        let auth_key_hash = match encrypted_master_key.auth_key_hash.as_ref() {
            Some(hash) => hash,
            None => {
                let _ = bcrypt::verify(&command.auth_key, DUMMY_BCRYPT_HASH);
                return Err(LoginPasswordUserError::InvalidCredentials);
            }
        };

        // Verify authKey against bcrypt hash
        let is_valid = bcrypt::verify(&command.auth_key, auth_key_hash)
            .map_err(|_| LoginPasswordUserError::InvalidCredentials)?;

        if !is_valid {
            return Err(LoginPasswordUserError::InvalidCredentials);
        }

        // Get encrypted identity keys
        let encrypted_identity_key = self
            .encrypted_identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(LoginPasswordUserError::EncryptedIdentityKeyRepository)?
            .ok_or(LoginPasswordUserError::InvalidCredentials)?;

        // Validate UMK data exists BEFORE creating session to prevent orphan sessions
        // Password users must have encrypted_umk; missing is a data inconsistency
        let encrypted_umk = encrypted_master_key
            .encrypted_umk
            .ok_or(LoginPasswordUserError::DataInconsistency)?;
        let umk_nonce = encrypted_master_key
            .umk_nonce
            .ok_or(LoginPasswordUserError::DataInconsistency)?;

        // Generate session token
        let session_token = generate_session_token();
        let token_hash = hash_session_token(&session_token);

        // Create session with device binding
        let session = Session::with_device(
            user.id,
            command.device_id,
            token_hash,
            command.remember_me,
            command.ip_address,
            command.user_agent,
        );

        // Save session
        self.session_repo
            .save(&session)
            .await
            .map_err(LoginPasswordUserError::SessionRepository)?;

        // Check if user has any active devices
        let devices = self
            .device_repo
            .find_active_by_user_id(user.id)
            .await
            .map_err(LoginPasswordUserError::DeviceRepository)?;
        let has_devices = !devices.is_empty();

        // Verify if the provided device_id is valid and belongs to this user
        let (device_verified, verified_device_id) = if let Some(device_id) = command.device_id {
            // Check if the device exists, is active, and belongs to this user
            let device_valid = devices.iter().any(|d| d.id == device_id);
            (device_valid, if device_valid { Some(device_id) } else { None })
        } else {
            (false, None)
        };

        // Only return encrypted keys if the device is verified
        // This prevents unverified/new devices from receiving UMK
        let keys = if device_verified {
            Some(LoginKeys {
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

        // Return result with encrypted keys only for verified devices
        Ok(LoginPasswordUserResult {
            user,
            session_token,
            expires_at: session.expires_at,
            has_devices,
            device_verified,
            device_id: verified_device_id,
            keys,
        })
    }
}

/// Generate a cryptographically secure session token
fn generate_session_token() -> String {
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
    let mut hex = String::with_capacity(64);
    for b in bytes {
        write!(&mut hex, "{:02x}", b).expect("Failed to write hex");
    }
    hex
}

/// Hash session token for storage
fn hash_session_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in hash {
        std::fmt::Write::write_fmt(&mut hex, format_args!("{:02x}", b))
            .expect("Failed to write hex");
    }
    hex
}
