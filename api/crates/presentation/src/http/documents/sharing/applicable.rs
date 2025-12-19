use axum::{
    Json,
    extract::{Query, State},
};

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;

use super::types::{ApplicableQuery, ApplicableShareItem, map_share_error};

#[utoipa::path(get, path = "/api/shares/applicable", tag = "Sharing",
    params(("doc_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "Shares that include the document", body = [ApplicableShareItem])))]
pub async fn list_applicable_shares(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Query(q): Query<ApplicableQuery>,
) -> Result<Json<Vec<ApplicableShareItem>>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_view(&actor, q.doc_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;

    let service = ctx.share_service();
    let rows = service
        .list_applicable(auth.workspace_id, &auth.permissions, q.doc_id)
        .await
        .map_err(map_share_error)?;
    let items: Vec<ApplicableShareItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(items))
}
