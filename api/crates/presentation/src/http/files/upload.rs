use axum::{
    Json,
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use domain::workspaces::permissions::PERM_FILE_UPLOAD;
use crate::context::AppContext;
use crate::http::auth::Bearer;
use crate::http::workspaces::scope as workspace_scope;

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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<UploadFileResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_FILE_UPLOAD)
        .await?;

    let mut document_id: Option<Uuid> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut orig_filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().map(|s| s.to_string());
        let file_name = field.file_name().map(|s| s.to_string());
        let ct = field.content_type().map(|s| s.to_string());
        match name.as_deref() {
            Some("document_id") => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                document_id = Uuid::parse_str(t.trim()).ok();
            }
            Some("file") => {
                orig_filename = file_name.clone();
                content_type = ct.clone();
                let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                if data.len() > ctx.cfg.upload_max_bytes {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                file_bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }

    let doc_id = document_id.ok_or(StatusCode::BAD_REQUEST)?;
    let bytes = file_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    let public_base_url = ctx.cfg.public_base_url.clone();
    let file_service = ctx.file_service();
    let f = file_service
        .upload_file(
            workspace_id,
            user_id,
            doc_id,
            bytes,
            orig_filename,
            content_type.clone(),
            public_base_url,
        )
        .await
        .map_err(map_file_error)?;
    Ok(Json(UploadFileResponse {
        id: f.id,
        url: f.url,
        filename: f.filename,
        content_type: f.content_type,
        size: f.size,
    }))
}
