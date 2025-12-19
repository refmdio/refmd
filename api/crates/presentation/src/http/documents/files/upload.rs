use axum::{
    Json,
    extract::{Multipart, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::domain::access::permissions::PERM_FILE_UPLOAD;

use super::types::{UploadFileResponse, map_file_error};

#[utoipa::path(
    post,
    path = "/api/files",
    tag = "Files",
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
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadFileResponse>), ApiError> {
    auth.ensure_permission(PERM_FILE_UPLOAD)?;

    let mut document_id: Option<Uuid> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut orig_filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("invalid_multipart"))?
    {
        let name = field.name().map(|s| s.to_string());
        let file_name = field.file_name().map(|s| s.to_string());
        let ct = field.content_type().map(|s| s.to_string());
        match name.as_deref() {
            Some("document_id") => {
                let t = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid_document_id"))?;
                document_id = Some(
                    Uuid::parse_str(t.trim())
                        .map_err(|_| ApiError::bad_request("invalid_document_id"))?,
                );
            }
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
            _ => {}
        }
    }

    let doc_id = document_id.ok_or(ApiError::bad_request("missing_document_id"))?;
    let bytes = file_bytes.ok_or(ApiError::bad_request("missing_file"))?;

    let public_base_url = ctx.cfg.public_base_url.clone();
    let file_service = ctx.file_service();
    let f = file_service
        .upload_file(
            auth.workspace_id,
            auth.user_id,
            doc_id,
            bytes,
            orig_filename,
            content_type.clone(),
            public_base_url,
        )
        .await
        .map_err(map_file_error)?;
    Ok((
        StatusCode::CREATED,
        Json(UploadFileResponse {
            id: f.id,
            url: f.url,
            filename: f.filename,
            content_type: f.content_type,
            size: f.size,
        }),
    ))
}
