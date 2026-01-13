use axum::{
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::core::services::errors::ServiceError;
use application::documents::services::files::FilePayload;

/// Response for file upload (E2EE format per design)
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UploadFileResponse {
    pub id: Uuid,
    /// URL to access the file (relative or absolute)
    pub url: String,
    /// Storage filename (UUID, for building relative paths)
    pub filename: String,
    /// SHA256 hash of encrypted file content
    pub encrypted_hash: String,
    pub size: i64,
}

pub fn map_file_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "file_service_error")
}

/// File payload response with optional E2EE metadata in headers.
/// For E2EE files, returns encrypted content with metadata headers for client-side decryption.
/// For legacy files, returns raw bytes without E2EE headers.
pub fn file_payload_response(payload: FilePayload) -> axum::response::Response {
    use base64::Engine;

    let mut headers = HeaderMap::new();
    // Use octet-stream for all files (client determines type from metadata or content)
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // Add E2EE metadata headers only if present
    if let Some(ref encrypted_metadata) = payload.encrypted_metadata {
        let encoded_metadata = base64::engine::general_purpose::STANDARD.encode(encrypted_metadata);
        if let Ok(val) = HeaderValue::from_str(&encoded_metadata) {
            headers.insert(
                axum::http::header::HeaderName::from_static("x-encrypted-metadata"),
                val,
            );
        }
    }
    if let Some(ref encrypted_metadata_nonce) = payload.encrypted_metadata_nonce {
        let encoded_nonce = base64::engine::general_purpose::STANDARD.encode(encrypted_metadata_nonce);
        if let Ok(val) = HeaderValue::from_str(&encoded_nonce) {
            headers.insert(
                axum::http::header::HeaderName::from_static("x-encrypted-metadata-nonce"),
                val,
            );
        }
    }
    if let Some(ref encrypted_hash) = payload.encrypted_hash {
        if let Ok(val) = HeaderValue::from_str(encrypted_hash) {
            headers.insert(
                axum::http::header::HeaderName::from_static("x-encrypted-hash"),
                val,
            );
        }
    }

    (headers, payload.bytes).into_response()
}

/// Multipart upload schema for OpenAPI
#[derive(ToSchema)]
#[allow(dead_code)]
pub struct UploadFileMultipart {
    /// Encrypted file binary (.rme format)
    #[schema(value_type = String, format = Binary)]
    pub file: String,
    /// JSON metadata containing encrypted file metadata
    #[schema(value_type = Option<String>)]
    pub metadata: Option<String>,
}

/// Metadata JSON structure for file upload
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadMetadata {
    /// Base64 encoded encrypted metadata
    pub encrypted_metadata: Option<String>,
    /// Base64 encoded nonce for encrypted metadata
    pub encrypted_metadata_nonce: Option<String>,
    /// Client-computed hash of encrypted file content (SHA256)
    pub encrypted_hash: Option<String>,
}

/// Response for listing files in a document.
/// Returns encrypted metadata for client-side decryption to build file map.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListFileResponse {
    pub id: Uuid,
    /// Base64 encoded encrypted metadata (contains filename, logicalPath, mimeType)
    pub encrypted_metadata: Option<String>,
    /// Base64 encoded nonce for encrypted metadata
    pub encrypted_metadata_nonce: Option<String>,
    /// SHA256 hash of encrypted file content
    pub encrypted_hash: Option<String>,
    /// File size in bytes
    pub size: i64,
}

