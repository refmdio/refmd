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
    /// SHA256 hash of encrypted file content
    pub encrypted_hash: String,
    pub size: i64,
}

pub fn map_file_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "file_service_error")
}

/// File payload response with optional E2EE metadata in headers
pub fn file_payload_response(payload: FilePayload) -> axum::response::Response {
    use base64::Engine;

    let mut headers = HeaderMap::new();
    if let Some(ct) = payload.content_type {
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(&ct)
                .unwrap_or(HeaderValue::from_static("application/octet-stream")),
        );
    }
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // Add E2EE metadata headers if present
    if let Some(encrypted_metadata) = payload.encrypted_metadata {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted_metadata);
        if let Ok(val) = HeaderValue::from_str(&encoded) {
            headers.insert(
                axum::http::header::HeaderName::from_static("x-encrypted-metadata"),
                val,
            );
        }
    }
    if let Some(nonce) = payload.encrypted_metadata_nonce {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&nonce);
        if let Ok(val) = HeaderValue::from_str(&encoded) {
            headers.insert(
                axum::http::header::HeaderName::from_static("x-encrypted-metadata-nonce"),
                val,
            );
        }
    }
    if let Some(hash) = payload.encrypted_hash {
        if let Ok(val) = HeaderValue::from_str(&hash) {
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

#[derive(Debug, Deserialize)]
pub struct FileByNameQuery {
    pub document_id: Uuid,
}
