use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use application::identity::dtos::{
    UserEncryptedMasterKeyDto, UserEncryptedPrivateKeyDto, UserPublicKeyDto,
};
use domain::identity::keys::{KdfParams, KdfType, KeyType};

// ============================================================================
// Public Key Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserPublicKeyResponse {
    #[schema(value_type = String, format = "byte")]
    pub public_key: String, // base64 encoded
    pub key_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserPublicKeyDto> for UserPublicKeyResponse {
    fn from(dto: UserPublicKeyDto) -> Self {
        use base64::Engine;
        Self {
            public_key: base64::engine::general_purpose::STANDARD.encode(&dto.public_key),
            key_type: dto.key_type.as_str().to_string(),
            created_at: dto.created_at,
            updated_at: dto.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPublicKeyRequest {
    /// Base64 encoded public key
    #[schema(value_type = String, format = "byte")]
    pub public_key: String,
    /// Key type (e.g., "ecdh-p256")
    #[schema(example = "ecdh-p256")]
    pub key_type: String,
}

impl RegisterPublicKeyRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, KeyType), &'static str> {
        use base64::Engine;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|_| "invalid_base64")?;
        let key_type = KeyType::parse(&self.key_type).ok_or("invalid_key_type")?;
        Ok((public_key, key_type))
    }
}

// ============================================================================
// Master Key Backup Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MasterKeyBackupResponse {
    #[schema(value_type = String, format = "byte")]
    pub encrypted_key: String, // base64 encoded
    #[schema(value_type = String, format = "byte")]
    pub salt: String, // base64 encoded
    pub kdf_type: String,
    pub kdf_params: KdfParamsResponse,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KdfParamsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
}

impl From<&KdfParams> for KdfParamsResponse {
    fn from(params: &KdfParams) -> Self {
        Self {
            memory: params.memory,
            iterations: params.iterations,
            parallelism: params.parallelism,
        }
    }
}

impl From<KdfParamsResponse> for KdfParams {
    fn from(resp: KdfParamsResponse) -> Self {
        Self {
            memory: resp.memory,
            iterations: resp.iterations,
            parallelism: resp.parallelism,
        }
    }
}

impl From<UserEncryptedMasterKeyDto> for MasterKeyBackupResponse {
    fn from(dto: UserEncryptedMasterKeyDto) -> Self {
        use base64::Engine;
        Self {
            encrypted_key: base64::engine::general_purpose::STANDARD.encode(&dto.encrypted_key),
            salt: base64::engine::general_purpose::STANDARD.encode(&dto.salt),
            kdf_type: dto.kdf_type.as_str().to_string(),
            kdf_params: KdfParamsResponse::from(&dto.kdf_params),
            created_at: dto.created_at,
            updated_at: dto.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreMasterKeyBackupRequest {
    /// Base64 encoded encrypted master key
    #[schema(value_type = String, format = "byte")]
    pub encrypted_key: String,
    /// Base64 encoded salt
    #[schema(value_type = String, format = "byte")]
    pub salt: String,
    /// KDF type (e.g., "argon2id", "pbkdf2")
    #[schema(example = "argon2id")]
    pub kdf_type: String,
    /// KDF parameters
    pub kdf_params: KdfParamsResponse,
}

impl StoreMasterKeyBackupRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>, KdfType, KdfParams), &'static str> {
        use base64::Engine;
        let encrypted_key = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_key)
            .map_err(|_| "invalid_encrypted_key_base64")?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&self.salt)
            .map_err(|_| "invalid_salt_base64")?;
        let kdf_type = KdfType::parse(&self.kdf_type).ok_or("invalid_kdf_type")?;
        let kdf_params = KdfParams::from(self.kdf_params.clone());
        Ok((encrypted_key, salt, kdf_type, kdf_params))
    }
}

// ============================================================================
// Encrypted Private Key Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPrivateKeyResponse {
    #[schema(value_type = String, format = "byte")]
    pub encrypted_private_key: String, // base64 encoded
    #[schema(value_type = String, format = "byte")]
    pub nonce: String, // base64 encoded
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserEncryptedPrivateKeyDto> for EncryptedPrivateKeyResponse {
    fn from(dto: UserEncryptedPrivateKeyDto) -> Self {
        use base64::Engine;
        Self {
            encrypted_private_key: base64::engine::general_purpose::STANDARD
                .encode(&dto.encrypted_private_key),
            nonce: base64::engine::general_purpose::STANDARD.encode(&dto.nonce),
            created_at: dto.created_at,
            updated_at: dto.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreEncryptedPrivateKeyRequest {
    /// Base64 encoded encrypted private key
    #[schema(value_type = String, format = "byte")]
    pub encrypted_private_key: String,
    /// Base64 encoded nonce
    #[schema(value_type = String, format = "byte")]
    pub nonce: String,
}

impl StoreEncryptedPrivateKeyRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use base64::Engine;
        let encrypted_private_key = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_private_key)
            .map_err(|_| "invalid_encrypted_private_key_base64")?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|_| "invalid_nonce_base64")?;
        Ok((encrypted_private_key, nonce))
    }
}
