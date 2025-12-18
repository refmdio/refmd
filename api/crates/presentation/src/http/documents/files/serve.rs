use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::security::token;
use application::core::services::access;

use super::types::file_payload_response;

/// Serve static files from uploads directory with authentication support
pub async fn serve_upload(
    State(ctx): State<AppContext>,
    AxumPath(path): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let share_token = params.get("token").cloned();
    let bearer = token::bearer_from_headers(&headers);

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Err(StatusCode::FORBIDDEN);
    }
    let doc_id = Uuid::parse_str(parts[0]).map_err(|_| StatusCode::FORBIDDEN)?;

    let actor = token::resolve_actor_from_parts(&ctx, bearer, share_token.as_deref())
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .unwrap_or(access::Actor::Public);
    let attachment_path = parts[1..].join("/");
    let payload = ctx
        .file_service()
        .serve_upload(&actor, doc_id, &attachment_path)
        .await
        .map_err(super::types::map_file_error)?;

    Ok(file_payload_response(payload))
}
