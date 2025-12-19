use axum::{
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::core::services::errors::ServiceError;
use application::documents::services::files::FilePayload;

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadFileResponse {
    pub id: Uuid,
    pub url: String,
    pub filename: String,
    pub content_type: Option<String>,
    pub size: i64,
}

pub fn map_file_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "file_service_error")
}

pub fn file_payload_response(payload: FilePayload) -> axum::response::Response {
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
    (headers, payload.bytes).into_response()
}

#[derive(ToSchema)]
#[allow(dead_code)]
pub struct UploadFileMultipart {
    #[schema(value_type = String, format = Binary)]
    pub file: String,
    #[schema(value_type = String, format = Uuid)]
    pub document_id: String,
}

#[derive(Debug, Deserialize)]
pub struct FileByNameQuery {
    pub document_id: Uuid,
}
