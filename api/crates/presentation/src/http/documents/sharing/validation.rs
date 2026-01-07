use axum::{
    Json,
    extract::{Query, State},
};
use base64::Engine;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;

use super::types::{ShareBrowseResponse, ShareDocumentResponse, ShareSaltResponse, ShareTokenQuery, map_share_error};

#[utoipa::path(
    get,
    path = "/api/shares/validate",
    tag = "Sharing",
    params(("token" = String, Query, description = "Share token")),
    responses((status = 200, description = "Document info", body = ShareDocumentResponse))
)]
pub async fn validate_share_token(
    State(ctx): State<DocumentsContext>,
    Query(query): Query<ShareTokenQuery>,
) -> Result<Json<ShareDocumentResponse>, ApiError> {
    let share_service = ctx.share_service();

    // Get basic share document info
    let res = share_service
        .validate_token(&query.token)
        .await
        .map_err(map_share_error)?;
    let mut out: ShareDocumentResponse = res
        .map(Into::into)
        .ok_or(ApiError::not_found("not_found"))?;

    // Get share context to obtain share_id for E2EE key lookup
    if let Ok(Some(share_ctx)) = share_service.resolve_share_context(&query.token).await {
        let keys_service = ctx.document_keys_service();
        if let Ok(Some(share_key)) = keys_service.get_share_key(share_ctx.share_id).await {
            out.encrypted_dek = Some(
                base64::engine::general_purpose::STANDARD.encode(&share_key.encrypted_dek),
            );
            if let Some(salt) = share_key.salt {
                out.salt = Some(base64::engine::general_purpose::STANDARD.encode(&salt));
            }
            if let Some(kdf_params) = share_key.kdf_params {
                out.kdf_params = serde_json::to_value(&kdf_params).ok();
            }
        }
    }

    Ok(Json(out))
}

/// Get salt for password-protected share (for password challenge)
#[utoipa::path(
    get,
    path = "/api/shares/salt",
    tag = "Sharing",
    params(("token" = String, Query, description = "Share token")),
    responses((status = 200, description = "Salt info for password-protected share", body = ShareSaltResponse))
)]
pub async fn get_share_salt(
    State(ctx): State<DocumentsContext>,
    Query(query): Query<ShareTokenQuery>,
) -> Result<Json<ShareSaltResponse>, ApiError> {
    let share_service = ctx.share_service();

    // First validate that the share token exists
    let share_ctx = share_service
        .resolve_share_context(&query.token)
        .await
        .map_err(map_share_error)?
        .ok_or(ApiError::not_found("not_found"))?;

    // Get share key info
    let keys_service = ctx.document_keys_service();
    let share_key = keys_service
        .get_share_key(share_ctx.share_id)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "failed_to_get_share_key");
            ApiError::not_found("not_found")
        })?;

    match share_key {
        Some(key) => {
            let password_protected = key.salt.is_some();
            Ok(Json(ShareSaltResponse {
                password_protected,
                salt: key.salt.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
                kdf_params: key.kdf_params.and_then(|p| serde_json::to_value(&p).ok()),
            }))
        }
        None => {
            // No E2EE key stored, share is not encrypted
            Ok(Json(ShareSaltResponse {
                password_protected: false,
                salt: None,
                kdf_params: None,
            }))
        }
    }
}

#[utoipa::path(get, path = "/api/shares/browse", tag = "Sharing",
    params(("token" = String, Query, description = "Share token")),
    responses((status = 200, description = "Share tree", body = ShareBrowseResponse)))]
pub async fn browse_share(
    State(ctx): State<DocumentsContext>,
    Query(query): Query<ShareTokenQuery>,
) -> Result<Json<ShareBrowseResponse>, ApiError> {
    let service = ctx.share_service();
    let res = service
        .browse_share(&query.token)
        .await
        .map_err(map_share_error)?;
    let out: ShareBrowseResponse = res
        .map(Into::into)
        .ok_or(ApiError::not_found("not_found"))?;
    Ok(Json(out))
}
