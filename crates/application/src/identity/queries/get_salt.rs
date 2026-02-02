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

/// Get salt query
#[derive(Debug)]
pub struct GetSaltQuery {
    pub email: String,
}

/// Get salt result
#[derive(Debug)]
pub struct GetSaltResult {
    /// Salt for KDF (32 bytes)
    pub salt: Vec<u8>,
    /// KDF type (always "argon2id")
    pub kdf_type: String,
    /// KDF parameters
    pub kdf_params: KdfParams,
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

impl<UR, UEM> GetSaltError<UR, UEM>
where
    UR: std::error::Error,
    UEM: std::error::Error,
{
    pub fn is_bad_request(&self) -> bool {
        matches!(self, GetSaltError::InvalidEmail(_))
    }
}

/// Get salt handler
pub struct GetSaltHandler<U, UEM> {
    user_repo: Arc<U>,
    encrypted_master_key_repo: Arc<UEM>,
    server_secret: Arc<[u8; 32]>,
}

impl<U, UEM> GetSaltHandler<U, UEM>
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

        // Try to find user and get their salt
        let salt = match self.user_repo.find_by_email(&email).await {
            Ok(Some(user)) => {
                // User exists, get their actual salt
                match self
                    .encrypted_master_key_repo
                    .find_by_user_id(user.id)
                    .await
                {
                    Ok(Some(umk)) => {
                        if let Some(salt) = umk.salt {
                            salt
                        } else {
                            // OAuth user or no salt - generate dummy
                            Self::generate_dummy_salt(&self.server_secret, normalized_email)
                        }
                    }
                    Ok(None) => {
                        // UMK not found - log warning and return dummy salt
                        tracing::warn!(user_id = %user.id, "UMK not found for existing user");
                        Self::generate_dummy_salt(&self.server_secret, normalized_email)
                    }
                    Err(e) => {
                        // Log error but return dummy salt to prevent enumeration
                        tracing::error!(user_id = %user.id, error = %e, "Failed to fetch UMK");
                        Self::generate_dummy_salt(&self.server_secret, normalized_email)
                    }
                }
            }
            Ok(None) => {
                // User doesn't exist - generate dummy salt
                // This prevents user enumeration attacks
                Self::generate_dummy_salt(&self.server_secret, normalized_email)
            }
            Err(e) => {
                // Log error but return dummy salt to prevent enumeration
                tracing::error!(email = %normalized_email, error = %e, "Failed to find user by email");
                Self::generate_dummy_salt(&self.server_secret, normalized_email)
            }
        };

        // Always return global KDF parameters (prevents enumeration via parameter differences)
        let kdf_params = KdfParams::default();

        Ok(GetSaltResult {
            salt,
            kdf_type: "argon2id".to_string(),
            kdf_params,
        })
    }

    /// Generate a deterministic dummy salt for unknown users
    /// Uses HMAC-SHA256(server_secret, email) to ensure consistent salt for same email
    fn generate_dummy_salt(server_secret: &[u8; 32], email: &str) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(server_secret).expect("HMAC can take key of any size");
        mac.update(b"dummy_salt:");
        mac.update(email.as_bytes());

        mac.finalize().into_bytes().to_vec()
    }
}
