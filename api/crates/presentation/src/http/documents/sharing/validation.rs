use axum::{
    Json,
    extract::{Query, State},
};

use crate::context::DocumentsContext;
use crate::http::error::ApiError;

use super::types::{ShareBrowseResponse, ShareDocumentResponse, ShareTokenQuery, map_share_error};

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
    let service = ctx.share_service();
    let res = service
        .validate_token(&query.token)
        .await
        .map_err(map_share_error)?;
    let out: ShareDocumentResponse = res
        .map(Into::into)
        .ok_or(ApiError::not_found("not_found"))?;
    Ok(Json(out))
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
