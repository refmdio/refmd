//! E2EE key types for user identity

use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const KDF_TYPE_ARGON2ID: &str = "argon2id";
pub const KDF_TYPE_PBKDF2: &str = "pbkdf2";
pub const KEY_TYPE_ECDH_P256: &str = "ecdh-p256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    Argon2id,
    Pbkdf2,
}

impl KdfType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            KDF_TYPE_ARGON2ID => Some(Self::Argon2id),
            KDF_TYPE_PBKDF2 => Some(Self::Pbkdf2),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => KDF_TYPE_ARGON2ID,
            Self::Pbkdf2 => KDF_TYPE_PBKDF2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    EcdhP256,
}

impl KeyType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            KEY_TYPE_ECDH_P256 => Some(Self::EcdhP256),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdhP256 => KEY_TYPE_ECDH_P256,
        }
    }
}

/// KDF parameters for key derivation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory: Some(65536),
            iterations: Some(3),
            parallelism: Some(4),
        }
    }
}

/// User's public key for ECDH key exchange
#[derive(Debug, Clone)]
pub struct UserPublicKey {
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub key_type: KeyType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User's encrypted master key (for recovery via passphrase)
#[derive(Debug, Clone)]
pub struct UserEncryptedMasterKey {
    pub user_id: Uuid,
    pub encrypted_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_type: KdfType,
    pub kdf_params: KdfParams,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User's encrypted private key (encrypted with UMK)
#[derive(Debug, Clone)]
pub struct UserEncryptedPrivateKey {
    pub user_id: Uuid,
    pub encrypted_private_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_type_parses() {
        assert_eq!(KdfType::parse("argon2id"), Some(KdfType::Argon2id));
        assert_eq!(KdfType::parse("pbkdf2"), Some(KdfType::Pbkdf2));
        assert_eq!(KdfType::parse("unknown"), None);
    }

    #[test]
    fn key_type_parses() {
        assert_eq!(KeyType::parse("ecdh-p256"), Some(KeyType::EcdhP256));
        assert_eq!(KeyType::parse("unknown"), None);
    }
}
