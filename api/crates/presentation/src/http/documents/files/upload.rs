use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::StatusCode,
};
use base64::Engine;
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::documents::use_cases::files::upload_file::FileUploadInput;
use domain::access::permissions::PERM_FILE_UPLOAD;

use super::types::{FileUploadMetadata, UploadFileResponse, map_file_error};

#[utoipa::path(
    post,
    path = "/api/documents/{docId}/files",
    tag = "Files",
    params(("docId" = Uuid, Path, description = "Document ID")),
    request_body(
        content = UploadFileMultipart,
        content_type = "multipart/form-data",
    ),
    responses(
        (status = 201, description = "File uploaded", body = UploadFileResponse)
    )
)]
pub async fn upload_file(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(doc_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadFileResponse>), ApiError> {
    auth.ensure_permission(PERM_FILE_UPLOAD)?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut orig_filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut metadata: Option<FileUploadMetadata> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("invalid_multipart"))?
    {
        let name = field.name().map(|s| s.to_string());
        let file_name = field.file_name().map(|s| s.to_string());
        let ct = field.content_type().map(|s| s.to_string());
        match name.as_deref() {
            Some("file") => {
                orig_filename = file_name.clone();
                content_type = ct.clone();
                let data = field
                    .bytes()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid_upload"))?;
                if data.len() > ctx.cfg.upload_max_bytes {
                    return Err(ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "payload_too_large",
                    ));
                }
                file_bytes = Some(data.to_vec());
            }
            Some("metadata") => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid_metadata"))?;
                metadata = serde_json::from_str(&text)
                    .map_err(|_| ApiError::bad_request("invalid_metadata_json"))?;
            }
            _ => {}
        }
    }

    let bytes = file_bytes.ok_or(ApiError::bad_request("missing_file"))?;

    // Extract E2EE fields from metadata
    let (encrypted_metadata, encrypted_metadata_nonce, encrypted_hash) = if let Some(m) = metadata {
        let em = m.encrypted_metadata.and_then(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(&s)
                .ok()
        });
        let emn = m.encrypted_metadata_nonce.and_then(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(&s)
                .ok()
        });
        (em, emn, m.encrypted_hash)
    } else {
        (None, None, None)
    };

    let public_base_url = ctx.cfg.public_base_url.clone();
    let file_service = ctx.file_service();

    // Upload file with optional E2EE metadata
    let input = FileUploadInput {
        bytes,
        orig_filename,
        content_type,
        encrypted_metadata,
        encrypted_metadata_nonce,
        encrypted_hash: encrypted_hash.clone(),
    };
    let f = file_service
        .upload_file(auth.workspace_id, auth.user_id, doc_id, input, public_base_url)
        .await
        .map_err(map_file_error)?;

    Ok((
        StatusCode::CREATED,
        Json(UploadFileResponse {
            id: f.id,
            encrypted_hash: f.encrypted_hash.unwrap_or_else(|| f.content_hash),
            size: f.size,
        }),
    ))
}
