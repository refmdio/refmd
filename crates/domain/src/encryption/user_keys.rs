//! User key entities

use chrono::{DateTime, Utc};

use super::value_objects::{AuthType, KdfParams, KdfType, PublicKeyPair};
use crate::identity::UserId;

/// User Identity public key
/// Long-term user identification key, shared across all devices.
#[derive(Debug, Clone)]
pub struct UserIdentityPublicKey {
    pub user_id: UserId,
    /// X25519 ECDH public key (32 bytes)
    pub ecdh_public_key: Vec<u8>,
    /// Ed25519 signing public key (32 bytes)
    pub signing_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserIdentityPublicKey {
    pub fn new(user_id: UserId, public_keys: PublicKeyPair) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            ecdh_public_key: public_keys.ecdh_public_key,
            signing_public_key: public_keys.signing_public_key,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn public_keys(&self) -> PublicKeyPair {
        PublicKeyPair::new(
            self.ecdh_public_key.clone(),
            self.signing_public_key.clone(),
        )
    }
}

/// User Encrypted Master Key (UMK)
/// UMK is randomly generated and encrypted with PUK (for password users) or only recovery key (for OAuth).
#[derive(Debug, Clone)]
pub struct UserEncryptedMasterKey {
    pub user_id: UserId,
    pub auth_type: AuthType,

    // Password user fields (nullable for OAuth users)
    /// Encrypted UMK (encrypted with PUK)
    pub encrypted_umk: Option<Vec<u8>>,
    /// Nonce for UMK encryption
    pub umk_nonce: Option<Vec<u8>>,
    /// Salt for KDF (PUK derivation)
    pub salt: Option<Vec<u8>>,
    /// KDF type
    pub kdf_type: Option<KdfType>,
    /// KDF parameters
    pub kdf_params: Option<KdfParams>,
    /// bcrypt hash of authKey
    pub auth_key_hash: Option<String>,

    // Recovery fields (required for all users)
    /// UMK encrypted with recovery key
    pub recovery_encrypted_umk: Vec<u8>,
    /// Nonce for recovery encryption
    pub recovery_nonce: Vec<u8>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a password user's encrypted master key
#[derive(Debug, Clone)]
pub struct PasswordUserMasterKeyParams {
    pub user_id: UserId,
    pub encrypted_umk: Vec<u8>,
    pub umk_nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub auth_key_hash: String,
    pub recovery_encrypted_umk: Vec<u8>,
    pub recovery_nonce: Vec<u8>,
}

impl UserEncryptedMasterKey {
    /// Create for password user
    pub fn new_password_user(params: PasswordUserMasterKeyParams) -> Self {
        let now = Utc::now();
        Self {
            user_id: params.user_id,
            auth_type: AuthType::Password,
            encrypted_umk: Some(params.encrypted_umk),
            umk_nonce: Some(params.umk_nonce),
            salt: Some(params.salt),
            kdf_type: Some(KdfType::Argon2id),
            kdf_params: Some(params.kdf_params),
            auth_key_hash: Some(params.auth_key_hash),
            recovery_encrypted_umk: params.recovery_encrypted_umk,
            recovery_nonce: params.recovery_nonce,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create for OAuth user (no password, only recovery key)
    pub fn new_oauth_user(
        user_id: UserId,
        recovery_encrypted_umk: Vec<u8>,
        recovery_nonce: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            auth_type: AuthType::OAuth,
            encrypted_umk: None,
            umk_nonce: None,
            salt: None,
            kdf_type: None,
            kdf_params: None,
            auth_key_hash: None,
            recovery_encrypted_umk,
            recovery_nonce,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_password_user(&self) -> bool {
        self.auth_type == AuthType::Password
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// User Encrypted Identity Key
/// Identity private keys encrypted with UMK.
#[derive(Debug, Clone)]
pub struct UserEncryptedIdentityKey {
    pub user_id: UserId,
    /// Encrypted ECDH private key
    pub encrypted_ecdh_private: Vec<u8>,
    /// Nonce for ECDH private key encryption
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    /// Encrypted signing private key
    pub encrypted_signing_private: Vec<u8>,
    /// Nonce for signing private key encryption
    pub encrypted_signing_private_nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserEncryptedIdentityKey {
    pub fn new(
        user_id: UserId,
        encrypted_ecdh_private: Vec<u8>,
        encrypted_ecdh_private_nonce: Vec<u8>,
        encrypted_signing_private: Vec<u8>,
        encrypted_signing_private_nonce: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            encrypted_ecdh_private,
            encrypted_ecdh_private_nonce,
            encrypted_signing_private,
            encrypted_signing_private_nonce,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}
