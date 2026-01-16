use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::Engine;
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;
use domain::documents::share::SHARE_PERMISSION_VIEW;
use domain::identity::keys::KdfParams;

use application::documents::dtos::ShareItemDto;

use super::types::{
    CreateShareRequest, CreateShareResponse, ShareItem, build_share_url, frontend_base,
    map_share_error,
};

#[utoipa::path(
    post,
    path = "/api/shares",
    tag = "Sharing",
    request_body = CreateShareRequest,
    responses((status = 200, description = "Share link created", body = CreateShareResponse))
)]
pub async fn create_share(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<CreateShareResponse>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, req.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let permission = req.permission.as_deref().unwrap_or(SHARE_PERMISSION_VIEW);
    let service = ctx.share_service();
    let res = service
        .create_share(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            req.document_id,
            permission,
            req.expires_at,
        )
        .await
        .map_err(map_share_error)?;

    // Store encrypted DEK if provided (E2EE mode)
    if let Some(encrypted_dek_b64) = req.encrypted_dek {
        let encrypted_dek = base64::engine::general_purpose::STANDARD
            .decode(&encrypted_dek_b64)
            .map_err(|_| ApiError::bad_request("invalid_encrypted_dek_base64"))?;

        // Decode creator_encrypted_share_key if provided
        let creator_encrypted_share_key = req
            .creator_encrypted_share_key
            .as_ref()
            .map(|s| base64::engine::general_purpose::STANDARD.decode(s))
            .transpose()
            .map_err(|_| ApiError::bad_request("invalid_creator_encrypted_share_key_base64"))?;
        let creator_share_key_nonce = req
            .creator_share_key_nonce
            .as_ref()
            .map(|s| base64::engine::general_purpose::STANDARD.decode(s))
            .transpose()
            .map_err(|_| ApiError::bad_request("invalid_creator_share_key_nonce_base64"))?;

        let keys_service = ctx.document_keys_service();

        if let (Some(salt_b64), Some(kdf_params_json)) = (req.salt, req.kdf_params) {
            // Password-protected share
            let salt = base64::engine::general_purpose::STANDARD
                .decode(&salt_b64)
                .map_err(|_| ApiError::bad_request("invalid_salt_base64"))?;
            let kdf_params: KdfParams = serde_json::from_value(kdf_params_json)
                .map_err(|_| ApiError::bad_request("invalid_kdf_params"))?;

            keys_service
                .store_password_protected_share_key(
                    res.share_id,
                    encrypted_dek,
                    salt,
                    kdf_params,
                    creator_encrypted_share_key,
                    creator_share_key_nonce,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = ?e, "failed_to_store_share_key");
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed_to_store_share_key")
                })?;
        } else {
            // URL fragment based share (no password)
            keys_service
                .store_share_key(
                    res.share_id,
                    encrypted_dek,
                    creator_encrypted_share_key,
                    creator_share_key_nonce,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = ?e, "failed_to_store_share_key");
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed_to_store_share_key")
                })?;
        }
    }

    let base = frontend_base(&ctx.cfg);
    let url = build_share_url(&base, &res.document_type, res.document_id, &res.token);
    Ok(Json(CreateShareResponse {
        token: res.token,
        url,
    }))
}

#[utoipa::path(
    get,
    path = "/api/shares/documents/{id}",
    tag = "Sharing",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "OK", body = [ShareItem]))
)]
pub async fn list_document_shares(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ShareItem>>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let service = ctx.share_service();
    let rows: Vec<ShareItemDto> = service
        .list_document_shares(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let items: Vec<ShareItem> = rows
        .into_iter()
        .map(|r| ShareItem::from_dto(&base, r))
        .collect();
    Ok(Json(items))
}

#[utoipa::path(
    delete,
    path = "/api/shares/{token}",
    tag = "Sharing",
    params(("token" = String, Path, description = "Share token")),
    responses((status = 204, description = "Share link deleted"))
)]
pub async fn delete_share(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(token): Path<String>,
) -> Result<StatusCode, ApiError> {
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    if meta.workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("forbidden"));
    }
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let ok = service
        .delete_share(auth.workspace_id, &auth.permissions, &token)
        .await
        .map_err(map_share_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("not_found"))
    }
}
