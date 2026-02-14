//! Recovery session command
//!
//! Creates a session for account recovery using Identity signature verification.
//! This allows users to recover their account without password (for OAuth users
//! or when password is forgotten).

use domain::encryption::{DeviceRepository, UserIdentityPublicKeyRepository};
use domain::identity::{Email, EmailError, Session, SessionRepository, UserRepository};
use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::UserDto;

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
    pub user: UserDto,
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

impl<UR, SR, UIP, DR> crate::types::AppError for RecoverySessionError<UR, SR, UIP, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UIP: std::error::Error,
    DR: std::error::Error,
{
    fn is_invalid_input(&self) -> bool {
        matches!(self, RecoverySessionError::InvalidEmail(_))
    }

    fn is_unauthenticated(&self) -> bool {
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
}

impl<UR, SR, UIP, DR> crate::types::SafeMessage for RecoverySessionError<UR, SR, UIP, DR>
where
    UR: std::error::Error,
    SR: std::error::Error,
    UIP: std::error::Error,
    DR: std::error::Error,
{
    /// Safe error message that doesn't leak user information
    /// All authentication failures return the same message to prevent user enumeration
    fn safe_message(&self) -> &'static str {
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

/// Map RecoveryChallengeError to RecoverySessionError
fn map_challenge_error<UR: std::error::Error, SR: std::error::Error, UIP: std::error::Error, DR: std::error::Error>(
    e: RecoveryChallengeError,
) -> RecoverySessionError<UR, SR, UIP, DR> {
    match e {
        RecoveryChallengeError::NotFound => RecoverySessionError::InvalidChallenge,
        RecoveryChallengeError::Expired => RecoverySessionError::ChallengeExpired,
        RecoveryChallengeError::StoreError => RecoverySessionError::ChallengeStoreError,
    }
}

/// Recovery session handler
pub struct RecoverySessionHandler<U: ?Sized, S: ?Sized, UIP: ?Sized, DR: ?Sized> {
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    identity_key_repo: Arc<UIP>,
    device_repo: Arc<DR>,
    recovery_challenge_store: Arc<dyn RecoveryChallengeStore>,
}

impl<U: ?Sized, S: ?Sized, UIP: ?Sized, DR: ?Sized> RecoverySessionHandler<U, S, UIP, DR>
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
        // Phase 1: Validate inputs
        let email = Email::new(&command.email)?;
        let challenge = Self::validate_inputs(&command)?;

        // Phase 2: Verify challenge, user identity, and signature
        let user = self.verify_identity(&command, &email, &challenge).await?;

        // Phase 3: Consume challenge (only after signature verified — DoS protection)
        self.recovery_challenge_store
            .consume(email.as_str(), &challenge)
            .await
            .map_err(map_challenge_error)?;

        // Phase 4: Create session and return result
        self.issue_session(user).await
    }

    /// Validate challenge length, signature length, and timestamp range.
    #[allow(clippy::type_complexity)]
    fn validate_inputs(
        command: &RecoverySessionCommand,
    ) -> Result<[u8; 32], RecoverySessionError<U::Error, S::Error, UIP::Error, DR::Error>> {
        if command.challenge.len() != 32 {
            return Err(RecoverySessionError::InvalidChallenge);
        }
        let challenge: [u8; 32] = command
            .challenge
            .clone()
            .try_into()
            .map_err(|_| RecoverySessionError::InvalidChallenge)?;
        if command.identity_signature.len() != 64 {
            return Err(RecoverySessionError::InvalidSignature);
        }
        let now = chrono::Utc::now().timestamp();
        let timestamp_age = now - command.timestamp;
        if !(-60..=300).contains(&timestamp_age) {
            return Err(RecoverySessionError::TimestampExpired);
        }
        Ok(challenge)
    }

    /// Verify challenge existence, find user, and verify Ed25519 signature.
    async fn verify_identity(
        &self,
        command: &RecoverySessionCommand,
        email: &Email,
        challenge: &[u8; 32],
    ) -> Result<domain::identity::User, RecoverySessionError<U::Error, S::Error, UIP::Error, DR::Error>> {
        self.recovery_challenge_store
            .verify(email.as_str(), challenge)
            .await
            .map_err(map_challenge_error)?;

        let user = self
            .user_repo
            .find_by_email(email)
            .await
            .map_err(RecoverySessionError::UserRepository)?
            .ok_or(RecoverySessionError::UserNotFound)?;

        let identity_key = self
            .identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(RecoverySessionError::IdentityKeyRepository)?
            .ok_or(RecoverySessionError::IdentityKeyNotFound)?;

        // Build signed message: "recovery-session:" || challenge || email || timestamp(LE)
        let mut message = Vec::new();
        message.extend_from_slice(b"recovery-session:");
        message.extend_from_slice(challenge);
        message.extend_from_slice(email.as_str().as_bytes());
        message.extend_from_slice(&command.timestamp.to_le_bytes());

        use crate::util::signature_verification::{verify_ed25519_signature, SignatureVerificationError};
        verify_ed25519_signature(
            &identity_key.signing_public_key,
            &command.identity_signature,
            &message,
        )
        .map_err(|e| match e {
            SignatureVerificationError::InvalidPublicKeyLength(_)
            | SignatureVerificationError::InvalidPublicKeyFormat => {
                tracing::error!("Invalid Ed25519 public key in database");
                RecoverySessionError::IdentityKeyNotFound
            }
            SignatureVerificationError::InvalidSignatureLength(_)
            | SignatureVerificationError::VerificationFailed => {
                RecoverySessionError::InvalidSignature
            }
        })?;

        Ok(user)
    }

    /// Create recovery session and check device status.
    async fn issue_session(
        &self,
        user: domain::identity::User,
    ) -> Result<RecoverySessionResult, RecoverySessionError<U::Error, S::Error, UIP::Error, DR::Error>> {
        let session_token =
            generate_session_token().map_err(RecoverySessionError::Rng)?;
        let token_hash = hash_session_token(&session_token);
        let session = Session::new_recovery(user.id, token_hash, None, None);
        self.session_repo
            .save(&session)
            .await
            .map_err(RecoverySessionError::SessionRepository)?;

        let devices = self
            .device_repo
            .find_active_by_user_id(user.id)
            .await
            .map_err(RecoverySessionError::DeviceRepository)?;

        Ok(RecoverySessionResult {
            user: user.into(),
            session_token,
            expires_at: session.expires_at,
            has_devices: !devices.is_empty(),
        })
    }
}

use crate::identity::session_token::{generate_session_token, hash_session_token};
