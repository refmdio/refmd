//! Get recovery data query handler
//!
//! Returns encrypted UMK (recovery-encrypted) for account recovery.
//! Also returns encrypted identity keys so user can fully restore access.
//!
//! Anti-enumeration: always returns plausible data (dummy on failure)
//! with constant-time response to prevent user enumeration.

use domain::encryption::{UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository};
use domain::identity::{Email, EmailError, UserRepository};
use std::sync::Arc;
use thiserror::Error;

/// Minimum response time to prevent timing-based user enumeration.
const MIN_RESPONSE_TIME: std::time::Duration = std::time::Duration::from_millis(50);

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

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("encrypted master key repository error: {0}")]
    EncryptedMasterKeyRepository(UEM),

    #[error("encrypted identity key repository error: {0}")]
    EncryptedIdentityKeyRepository(UEI),

    #[error("random number generation failed")]
    Rng,
}

impl<UR, UEM, UEI> crate::types::AppError for GetRecoveryDataError<UR, UEM, UEI>
where
    UR: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
{
    fn is_invalid_input(&self) -> bool {
        matches!(self, GetRecoveryDataError::InvalidEmail(_))
    }
}

/// Get recovery data handler
pub struct GetRecoveryDataHandler<U: ?Sized, UEM: ?Sized, UEI: ?Sized> {
    user_repo: Arc<U>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    /// Server secret for HMAC-based dummy user_id generation (anti-enumeration)
    server_secret: Arc<[u8; 32]>,
}

impl<U: ?Sized, UEM: ?Sized, UEI: ?Sized> GetRecoveryDataHandler<U, UEM, UEI>
where
    U: UserRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
        server_secret: Arc<[u8; 32]>,
    ) -> Self {
        Self {
            user_repo,
            encrypted_master_key_repo,
            encrypted_identity_key_repo,
            server_secret,
        }
    }

    pub async fn handle(
        &self,
        query: GetRecoveryDataQuery,
    ) -> Result<GetRecoveryDataResult, GetRecoveryDataError<U::Error, UEM::Error, UEI::Error>> {
        let start = tokio::time::Instant::now();

        let result = self.handle_inner(query).await;

        // Timing attack mitigation: ensure minimum response time
        // to prevent distinguishing existing vs non-existing users
        let elapsed = start.elapsed();
        if elapsed < MIN_RESPONSE_TIME {
            tokio::time::sleep(MIN_RESPONSE_TIME - elapsed).await;
        }

        result
    }

    async fn handle_inner(
        &self,
        query: GetRecoveryDataQuery,
    ) -> Result<GetRecoveryDataResult, GetRecoveryDataError<U::Error, UEM::Error, UEI::Error>> {
        // Validate email format (this can return a bad_request error)
        let email = Email::new(&query.email)?;

        // Find user by email
        let user = match self
            .user_repo
            .find_by_email(&email)
            .await
            .map_err(GetRecoveryDataError::UserRepository)?
        {
            Some(u) => u,
            None => return self.generate_dummy_result(&email),
        };

        // Get encrypted master key (for recovery data)
        let umk = match self
            .encrypted_master_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(GetRecoveryDataError::EncryptedMasterKeyRepository)?
        {
            Some(umk) if !umk.recovery_encrypted_umk.is_empty() && !umk.recovery_nonce.is_empty() => umk,
            _ => return self.generate_dummy_result(&email),
        };

        // Get encrypted identity keys
        let identity_keys = match self
            .encrypted_identity_key_repo
            .find_by_user_id(user.id)
            .await
            .map_err(GetRecoveryDataError::EncryptedIdentityKeyRepository)?
        {
            Some(keys) => keys,
            None => return self.generate_dummy_result(&email),
        };

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

    /// Generate dummy recovery data indistinguishable from real data.
    /// Client will fail at decryption (wrong recovery key), not at HTTP level.
    ///
    /// The dummy user_id is deterministic per-email (via HMAC-SHA256 with server
    /// secret) so repeated queries for the same non-existent email always return
    /// the same user_id, preventing enumeration by comparing responses. The server
    /// secret ensures attackers cannot pre-compute the expected dummy user_id.
    #[allow(clippy::type_complexity)]
    fn generate_dummy_result(
        &self,
        email: &Email,
    ) -> Result<GetRecoveryDataResult, GetRecoveryDataError<U::Error, UEM::Error, UEI::Error>> {
        let mut buf = [0u8; 48 + 24 + 48 + 24 + 48 + 24]; // 216 bytes total
        getrandom::fill(&mut buf).map_err(|_| GetRecoveryDataError::Rng)?;

        // Deterministic dummy ID using HMAC-SHA256 with server secret
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.server_secret.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(b"recovery-dummy-id:");
        mac.update(email.as_str().as_bytes());
        let hash = mac.finalize().into_bytes();
        let dummy_id = uuid::Uuid::from_bytes(hash[..16].try_into().unwrap());

        Ok(GetRecoveryDataResult {
            user_id: dummy_id,
            recovery_encrypted_umk: buf[0..48].to_vec(),
            recovery_nonce: buf[48..72].to_vec(),
            encrypted_ecdh_private: buf[72..120].to_vec(),
            encrypted_ecdh_private_nonce: buf[120..144].to_vec(),
            encrypted_signing_private: buf[144..192].to_vec(),
            encrypted_signing_private_nonce: buf[192..216].to_vec(),
        })
    }
}
