use chrono::{DateTime, Utc};

use domain::encryption::DeviceId;
use domain::identity::{Session, SessionId, User, UserId};
use domain::encryption::{UserEncryptedIdentityKey, UserEncryptedMasterKey};

/// DTO for User entity
#[derive(Debug, Clone)]
pub struct UserDto {
    pub id: UserId,
    pub email: String,
    pub name: String,
    pub encryption_setup_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserDto {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email.to_string(),
            name: u.name,
            encryption_setup_at: u.encryption_setup_at,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// DTO for Session entity
#[derive(Debug, Clone)]
pub struct SessionDto {
    pub id: SessionId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub remember_me: bool,
    pub is_recovery: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<Session> for SessionDto {
    fn from(s: Session) -> Self {
        Self {
            id: s.id,
            user_id: s.user_id,
            device_id: s.device_id,
            token_hash: s.token_hash,
            remember_me: s.remember_me,
            is_recovery: s.is_recovery,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            expires_at: s.expires_at,
            created_at: s.created_at,
        }
    }
}

/// DTO for UserEncryptedMasterKey entity
#[derive(Debug, Clone)]
pub struct UserEncryptedMasterKeyDto {
    pub user_id: UserId,
    pub auth_type: String,
    pub encrypted_umk: Option<Vec<u8>>,
    pub umk_nonce: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub kdf_type: Option<String>,
    pub kdf_params: Option<KdfParamsDto>,
    pub auth_key_hash: Option<String>,
    pub recovery_encrypted_umk: Vec<u8>,
    pub recovery_nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserEncryptedMasterKeyDto {
    pub fn is_password_user(&self) -> bool {
        self.auth_type == "password"
    }
}

impl From<UserEncryptedMasterKey> for UserEncryptedMasterKeyDto {
    fn from(k: UserEncryptedMasterKey) -> Self {
        Self {
            user_id: k.user_id,
            auth_type: k.auth_type.as_str().to_string(),
            encrypted_umk: k.encrypted_umk,
            umk_nonce: k.umk_nonce,
            salt: k.salt,
            kdf_type: k.kdf_type.map(|t| t.as_str().to_string()),
            kdf_params: k.kdf_params.map(Into::into),
            auth_key_hash: k.auth_key_hash,
            recovery_encrypted_umk: k.recovery_encrypted_umk,
            recovery_nonce: k.recovery_nonce,
            created_at: k.created_at,
            updated_at: k.updated_at,
        }
    }
}

/// DTO for KdfParams value object
#[derive(Debug, Clone)]
pub struct KdfParamsDto {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl From<domain::encryption::KdfParams> for KdfParamsDto {
    fn from(p: domain::encryption::KdfParams) -> Self {
        Self {
            memory_cost: p.memory_cost,
            time_cost: p.time_cost,
            parallelism: p.parallelism,
        }
    }
}

/// DTO for UserEncryptedIdentityKey entity
#[derive(Debug, Clone)]
pub struct UserEncryptedIdentityKeyDto {
    pub user_id: UserId,
    pub encrypted_ecdh_private: Vec<u8>,
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    pub encrypted_signing_private: Vec<u8>,
    pub encrypted_signing_private_nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserEncryptedIdentityKey> for UserEncryptedIdentityKeyDto {
    fn from(k: UserEncryptedIdentityKey) -> Self {
        Self {
            user_id: k.user_id,
            encrypted_ecdh_private: k.encrypted_ecdh_private,
            encrypted_ecdh_private_nonce: k.encrypted_ecdh_private_nonce,
            encrypted_signing_private: k.encrypted_signing_private,
            encrypted_signing_private_nonce: k.encrypted_signing_private_nonce,
            created_at: k.created_at,
            updated_at: k.updated_at,
        }
    }
}
