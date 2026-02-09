//! Recovery session command
//!
//! Creates a session for account recovery using Identity signature verification.
//! This allows users to recover their account without password (for OAuth users
//! or when password is forgotten).

use domain::encryption::{DeviceRepository, UserIdentityPublicKeyRepository};
use domain::identity::{Email, EmailError, Session, SessionRepository, User, UserRepository};
use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
use ed25519_dalek::{Signature, VerifyingKey};
use std::sync::Arc;
use thiserror::Error;

/// Recovery session command
#[derive(Debug)]
pub struct RecoverySessionCommand {
    pub email: String,
    /// Server-issued challenge (32 bytes)
    pub challenge: Vec<u8>,
    /// Ed25519 signature of the recovery session message
    pub identity_signature: Vec<u8>,
    /// Unix timestamp (seconds) included in signed message
    pub timestamp: i64,
}

/// Recovery session result
#[derive(Debug)]
pub struct RecoverySessionResult {
    pub user: User,
    pub session_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether user has any registered devices
    pub has_devices: bool,
}

/// Recovery session error
#[derive(Debug, Error)]
pub enum RecoverySessionError<
    UR: std::error::Error,
    SR: std::error::Error,
    UIP: std::error::Error,
    DR: std::error::Error,
> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("invalid challenge")]
    InvalidChallenge,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("timestamp too old")]
    TimestampExpired,

    #[error("user not found")]
    UserNotFound,

    #[error("identity key not found")]
    IdentityKeyNotFound,

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("session repository error: {0}")]
    SessionRepository(SR),

    #[error("identity key repository error: {0}")]
    IdentityKeyRepository(UIP),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("challenge store error")]
    ChallengeStoreError,

    #[error("random number generator error: {0}")]
    Rng(getrandom::Error),
}

impl<UR, SR, UIP, DR> RecoverySessionError<UR, SR, UIP, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UIP: std::error::Error,
    DR: std::error::Error,
{
    pub fn is_bad_request(&self) -> bool {
        matches!(self, RecoverySessionError::InvalidEmail(_))
    }

    pub fn is_unauthorized(&self) -> bool {
        // All authentication-related errors return 401 to prevent user enumeration
        matches!(
            self,
            RecoverySessionError::InvalidChallenge
                | RecoverySessionError::ChallengeExpired
                | RecoverySessionError::InvalidSignature
                | RecoverySessionError::TimestampExpired
                | RecoverySessionError::UserNotFound
                | RecoverySessionError::IdentityKeyNotFound
        )
    }

    /// Safe error message that doesn't leak user information
    /// All authentication failures return the same message to prevent user enumeration
    pub fn safe_message(&self) -> &'static str {
        match self {
            // Format error - safe to be specific (HTTP 400)
            RecoverySessionError::InvalidEmail(_) => "invalid email",
            // All authentication failures return the same message (HTTP 401)
            // This prevents attackers from distinguishing between:
            // - Invalid challenge, expired challenge, invalid signature
            // - Non-existent user, missing identity keys
            RecoverySessionError::InvalidChallenge
            | RecoverySessionError::ChallengeExpired
            | RecoverySessionError::InvalidSignature
            | RecoverySessionError::TimestampExpired
            | RecoverySessionError::UserNotFound
            | RecoverySessionError::IdentityKeyNotFound => "invalid or expired recovery request",
            // Internal errors (HTTP 500)
            RecoverySessionError::UserRepository(_)
            | RecoverySessionError::SessionRepository(_)
            | RecoverySessionError::IdentityKeyRepository(_)
            | RecoverySessionError::DeviceRepository(_)
            | RecoverySessionError::ChallengeStoreError
            | RecoverySessionError::Rng(_) => "internal server error",
        }
    }
}

/// Recovery session handler
pub struct RecoverySessionHandler<U, S, UIP, DR> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    identity_key_repo: Arc<UIP>,
    device_repo: Arc<DR>,
    recovery_challenge_store: Arc<dyn RecoveryChallengeStore>,
}

impl<U, S, UIP, DR> RecoverySessionHandler<U, S, UIP, DR>
where
    U: UserRepository,
    S: SessionRepository,
    UIP: UserIdentityPublicKeyRepository,
    DR: DeviceRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        session_repo: Arc<S>,
        identity_key_repo: Arc<UIP>,
        device_repo: Arc<DR>,
        recovery_challenge_store: Arc<dyn RecoveryChallengeStore>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            identity_key_repo,
            device_repo,
            recovery_challenge_store,
        }
    }

    pub async fn handle(
        &self,
        command: RecoverySessionCommand,
    ) -> Result<RecoverySessionResult, RecoverySessionError<U::Error, S::Error, UIP::Error, DR::Error>>
    {
        // Validate email format
        let email = Email::new(&command.email)?;

        // Validate challenge length
        if command.challenge.len() != 32 {
            return Err(RecoverySessionError::InvalidChallenge);
        }
        let challenge: [u8; 32] = command
            .challenge
            .try_into()
            .map_err(|_| RecoverySessionError::InvalidChallenge)?;

        // Validate signature length
        if command.identity_signature.len() != 64 {
            return Err(RecoverySessionError::InvalidSignature);
        }

        // Validate timestamp (must be within 5 minutes of current time)
        let now = chrono::Utc::now().timestamp();
        let timestamp_age = now - command.timestamp;
        if timestamp_age > 300 || timestamp_age < -60 {
            // Allow 1 minute clock skew into the future
            return Err(RecoverySessionError::TimestampExpired);
        }

        // Step 1: Verify challenge exists (don't consume yet - DoS protection)
        self.recovery_challenge_store
            .verify(&command.email, &challenge)
            .await
            .map_err(|e| match e {
                RecoveryChallengeError::NotFound => RecoverySessionError::InvalidChallenge,
                RecoveryChallengeError::Expired => RecoverySessionError::ChallengeExpired,
                RecoveryChallengeError::StoreError => RecoverySessionError::ChallengeStoreError,
            })?;

        // Step 2: Find user by email
        let user = self
            .user_repo
            .find_by_email(&email)
            .await
            .map_err(RecoverySessionError::UserRepository)?
            .ok_or(RecoverySessionError::UserNotFound)?;

        // Step 3: Get user's identity public key
        let identity_key = self
            .identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(RecoverySessionError::IdentityKeyRepository)?
            .ok_or(RecoverySessionError::IdentityKeyNotFound)?;

        // Step 4: Build message that should have been signed:
        // "recovery-session:" || challenge(32) || email || timestamp(8, LE)
        let mut message = Vec::new();
        message.extend_from_slice(b"recovery-session:");
        message.extend_from_slice(&challenge);
        message.extend_from_slice(command.email.to_lowercase().as_bytes());
        message.extend_from_slice(&command.timestamp.to_le_bytes());

        // Step 5: Verify Ed25519 signature
        let verifying_key =
            VerifyingKey::from_bytes(&identity_key.signing_public_key.try_into().map_err(|_| {
                tracing::error!("Invalid signing public key length in database");
                RecoverySessionError::IdentityKeyNotFound
            })?)
            .map_err(|_| {
                tracing::error!("Invalid Ed25519 public key in database");
                RecoverySessionError::IdentityKeyNotFound
            })?;

        let signature = Signature::from_bytes(
            &command
                .identity_signature
                .try_into()
                .map_err(|_| RecoverySessionError::InvalidSignature)?,
        );

        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| RecoverySessionError::InvalidSignature)?;

        // Step 6: Only after signature verification succeeds, consume the challenge
        // This prevents DoS attacks where attackers consume challenges with invalid signatures
        self.recovery_challenge_store
            .consume(&command.email, &challenge)
            .await
            .map_err(|e| match e {
                RecoveryChallengeError::NotFound => RecoverySessionError::InvalidChallenge,
                RecoveryChallengeError::Expired => RecoverySessionError::ChallengeExpired,
                RecoveryChallengeError::StoreError => RecoverySessionError::ChallengeStoreError,
            })?;

        // Generate session token
        let session_token =
            generate_session_token().map_err(RecoverySessionError::Rng)?;
        let token_hash = hash_session_token(&session_token);

        // Create recovery session (no device binding, is_recovery = true)
        let session = Session::new_recovery(user.id, token_hash, None, None);

        // Save session
        self.session_repo
            .save(&session)
            .await
            .map_err(RecoverySessionError::SessionRepository)?;

        // Check if user has any active devices
        let devices = self
            .device_repo
            .find_active_by_user_id(user.id)
            .await
            .map_err(RecoverySessionError::DeviceRepository)?;
        let has_devices = !devices.is_empty();

        Ok(RecoverySessionResult {
            user,
            session_token,
            expires_at: session.expires_at,
            has_devices,
        })
    }
}

/// Generate a cryptographically secure session token
fn generate_session_token() -> Result<String, getrandom::Error> {
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let mut hex = String::with_capacity(64);
    for b in bytes {
        write!(&mut hex, "{:02x}", b).expect("Failed to write hex");
    }
    Ok(hex)
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
