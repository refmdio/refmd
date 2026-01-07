use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::documents::dtos::{DocumentEncryptedKeyDto, ShareEncryptedKeyDto};
use domain::identity::keys::KdfParams;

// ============================================================================
// Document Key Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentKeyResponse {
    pub document_id: Uuid,
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String, // base64 encoded
    #[schema(value_type = String, format = "byte")]
    pub nonce: String, // base64 encoded
    pub key_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<DocumentEncryptedKeyDto> for DocumentKeyResponse {
    fn from(dto: DocumentEncryptedKeyDto) -> Self {
        use base64::Engine;
        Self {
            document_id: dto.document_id,
            encrypted_dek: base64::engine::general_purpose::STANDARD.encode(&dto.encrypted_dek),
            nonce: base64::engine::general_purpose::STANDARD.encode(&dto.nonce),
            key_version: dto.key_version,
            created_at: dto.created_at,
            updated_at: dto.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreDocumentKeyRequest {
    /// Base64 encoded encrypted DEK
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
    /// Base64 encoded nonce
    #[schema(value_type = String, format = "byte")]
    pub nonce: String,
    /// Key version
    pub key_version: i32,
}

impl StoreDocumentKeyRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use base64::Engine;
        let encrypted_dek = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_dek)
            .map_err(|_| "invalid_encrypted_dek_base64")?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|_| "invalid_nonce_base64")?;
        Ok((encrypted_dek, nonce))
    }
}

// ============================================================================
// Share Key Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareKeyResponse {
    pub share_id: Uuid,
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String, // base64 encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub salt: Option<String>, // base64 encoded, for password-protected shares
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<KdfParamsResponse>,
    pub is_password_protected: bool,
    pub created_at: DateTime<Utc>,
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

impl From<ShareEncryptedKeyDto> for ShareKeyResponse {
    fn from(dto: ShareEncryptedKeyDto) -> Self {
        use base64::Engine;
        let is_password_protected = dto.is_password_protected();
        Self {
            share_id: dto.share_id,
            encrypted_dek: base64::engine::general_purpose::STANDARD.encode(&dto.encrypted_dek),
            salt: dto.salt.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
            kdf_params: dto.kdf_params.as_ref().map(KdfParamsResponse::from),
            is_password_protected,
            created_at: dto.created_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreShareKeyRequest {
    /// Base64 encoded encrypted DEK
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
}

impl StoreShareKeyRequest {
    pub fn decode(&self) -> Result<Vec<u8>, &'static str> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_dek)
            .map_err(|_| "invalid_encrypted_dek_base64")
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorePasswordProtectedShareKeyRequest {
    /// Base64 encoded encrypted DEK
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
    /// Base64 encoded salt
    #[schema(value_type = String, format = "byte")]
    pub salt: String,
    /// KDF parameters
    pub kdf_params: KdfParamsResponse,
}

impl StorePasswordProtectedShareKeyRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>, KdfParams), &'static str> {
        use base64::Engine;
        let encrypted_dek = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_dek)
            .map_err(|_| "invalid_encrypted_dek_base64")?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&self.salt)
            .map_err(|_| "invalid_salt_base64")?;
        let kdf_params = KdfParams::from(self.kdf_params.clone());
        Ok((encrypted_dek, salt, kdf_params))
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareSaltResponse {
    pub share_id: Uuid,
    #[schema(value_type = Option<String>, format = "byte")]
    pub salt: Option<String>, // base64 encoded
}

// ============================================================================
// Document Key Rotation Types
// ============================================================================

/// Request body for document DEK rotation
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RotateDocumentKeyRequest {
    /// Base64 encoded new encrypted DEK
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
    /// Base64 encoded nonce
    #[schema(value_type = String, format = "byte")]
    pub nonce: String,
}

impl RotateDocumentKeyRequest {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use base64::Engine;
        let encrypted_dek = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_dek)
            .map_err(|_| "invalid_encrypted_dek_base64")?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|_| "invalid_nonce_base64")?;
        Ok((encrypted_dek, nonce))
    }
}

/// Response for document DEK rotation
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RotateDocumentKeyResponse {
    pub document_id: Uuid,
    pub new_key_version: i32,
}
