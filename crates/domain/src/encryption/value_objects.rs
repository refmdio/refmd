//! Encryption domain value objects

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Device ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Device type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Browser,
    Desktop,
    Mobile,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Browser => "browser",
            DeviceType::Desktop => "desktop",
            DeviceType::Mobile => "mobile",
        }
    }
}

impl std::str::FromStr for DeviceType {
    type Err = DeviceTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "browser" => Ok(DeviceType::Browser),
            "desktop" => Ok(DeviceType::Desktop),
            "mobile" => Ok(DeviceType::Mobile),
            _ => Err(DeviceTypeError::InvalidType(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceTypeError {
    #[error("invalid device type: {0}")]
    InvalidType(String),
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Password,
    OAuth,
}

impl AuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthType::Password => "password",
            AuthType::OAuth => "oauth",
        }
    }
}

impl std::str::FromStr for AuthType {
    type Err = AuthTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "password" => Ok(AuthType::Password),
            "oauth" => Ok(AuthType::OAuth),
            _ => Err(AuthTypeError::InvalidType(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthTypeError {
    #[error("invalid auth type: {0}")]
    InvalidType(String),
}

/// KDF type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfType {
    Argon2id,
}

impl KdfType {
    pub fn as_str(&self) -> &'static str {
        match self {
            KdfType::Argon2id => "argon2id",
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = KdfTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "argon2id" => Ok(KdfType::Argon2id),
            _ => Err(KdfTypeError::InvalidType(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KdfTypeError {
    #[error("invalid KDF type: {0}")]
    InvalidType(String),
}

/// Key version (for KEK/DEK rotation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyVersion(i32);

impl KeyVersion {
    pub fn new(version: i32) -> Self {
        Self(version)
    }

    pub fn initial() -> Self {
        Self(1)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_i32(&self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// KDF parameters for Argon2id
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // OWASP recommended parameters for Argon2id
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Encrypted data with nonce
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptedData {
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self { ciphertext, nonce }
    }
}

/// Public key pair (ECDH + Signing)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPair {
    /// X25519 ECDH public key (32 bytes)
    pub ecdh_public_key: Vec<u8>,
    /// Ed25519 signing public key (32 bytes)
    pub signing_public_key: Vec<u8>,
}

impl PublicKeyPair {
    pub fn new(ecdh_public_key: Vec<u8>, signing_public_key: Vec<u8>) -> Self {
        Self {
            ecdh_public_key,
            signing_public_key,
        }
    }
}
