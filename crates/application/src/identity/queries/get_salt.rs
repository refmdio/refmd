//! Get salt query handler
//!
//! Returns salt and KDF parameters for password authentication.
//! For unknown users, returns a deterministic dummy salt to prevent user enumeration.

use domain::encryption::{KdfParams, UserEncryptedMasterKeyRepository};
use domain::identity::{Email, EmailError, UserRepository};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use thiserror::Error;

use crate::dto::KdfParamsDto;

/// Get salt query
#[derive(Debug)]
pub struct GetSaltQuery {
    pub email: String,
}

/// Get salt result
#[derive(Debug)]
pub struct GetSaltResult {
    /// Salt for KDF (16 bytes per spec)
    pub salt: Vec<u8>,
    /// KDF type (always "argon2id")
    pub kdf_type: String,
    /// KDF parameters
    pub kdf_params: KdfParamsDto,
}

/// Get salt error
#[derive(Debug, Error)]
pub enum GetSaltError<UR: std::error::Error, UEM: std::error::Error> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("encrypted master key repository error: {0}")]
    EncryptedMasterKeyRepository(UEM),
}

impl<UR, UEM> crate::types::AppError for GetSaltError<UR, UEM>
where
    UR: std::error::Error,
    UEM: std::error::Error,
{
    fn is_invalid_input(&self) -> bool {
        matches!(self, GetSaltError::InvalidEmail(_))
    }
}

/// Get salt handler
pub struct GetSaltHandler<U: ?Sized, UEM: ?Sized> {
    user_repo: Arc<U>,
    encrypted_master_key_repo: Arc<UEM>,
    server_secret: Arc<[u8; 32]>,
}

impl<U: ?Sized, UEM: ?Sized> GetSaltHandler<U, UEM>
where
    U: UserRepository,
    UEM: UserEncryptedMasterKeyRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        encrypted_master_key_repo: Arc<UEM>,
        server_secret: Arc<[u8; 32]>,
    ) -> Self {
        Self {
            user_repo,
            encrypted_master_key_repo,
            server_secret,
        }
    }

    pub async fn handle(
        &self,
        query: GetSaltQuery,
    ) -> Result<GetSaltResult, GetSaltError<U::Error, UEM::Error>> {
        // Validate email format
        let email = Email::new(&query.email)?;

        // Use normalized email for dummy salt (prevents enumeration via case differences)
        let normalized_email = email.as_str();

        let salt = self
            .try_get_real_salt(&email)
            .await
            .unwrap_or_else(|| Self::generate_dummy_salt(&self.server_secret, normalized_email));

        // Always return global KDF parameters (prevents enumeration via parameter differences)
        let kdf_params = KdfParams::default();

        Ok(GetSaltResult {
            salt,
            kdf_type: "argon2id".to_string(),
            kdf_params: kdf_params.into(),
        })
    }

    /// Try to retrieve the real salt for a known user.
    /// Returns `None` (falling back to dummy salt) on any error or missing data
    /// to prevent user enumeration.
    async fn try_get_real_salt(&self, email: &Email) -> Option<Vec<u8>> {
        let user = match self.user_repo.find_by_email(email).await {
            Ok(Some(user)) => user,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(email = %email.as_str(), error = %e, "Failed to find user by email");
                return None;
            }
        };

        let umk = match self.encrypted_master_key_repo.find_by_user_id(user.id).await {
            Ok(Some(umk)) => umk,
            Ok(None) => {
                tracing::warn!(user_id = %user.id, "UMK not found for existing user");
                return None;
            }
            Err(e) => {
                tracing::error!(user_id = %user.id, error = %e, "Failed to fetch UMK");
                return None;
            }
        };

        umk.salt
    }

    /// Generate a deterministic dummy salt for unknown users
    /// Uses HMAC-SHA256(server_secret, email) truncated to 16 bytes
    /// to match Argon2id salt length per spec
    fn generate_dummy_salt(server_secret: &[u8; 32], email: &str) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(server_secret).expect("HMAC can take key of any size");
        mac.update(b"dummy_salt:");
        mac.update(email.as_bytes());

        // Truncate to 16 bytes per spec (Argon2id salt length)
        mac.finalize().into_bytes()[..16].to_vec()
    }
}
