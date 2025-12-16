use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use application::access;
use crate::context::AppContext;
use crate::http::auth::{self, Bearer};

use super::types::file_payload_response;

/// Serve static files from uploads directory with authentication support
pub async fn serve_upload(
    State(ctx): State<AppContext>,
    AxumPath(path): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let share_token = params.get("token").cloned();
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|s| s.to_string()))
        .or_else(|| {
            headers
                .get(axum::http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|cookie_hdr| {
                    for part in cookie_hdr.split(';') {
                        let kv = part.trim();
                        if let Some((k, v)) = kv.split_once('=') {
                            if k.trim() == "access_token" {
                                return Some(v.trim().to_string());
                            }
                        }
                    }
                    None
                })
        });
    let bearer = bearer_token.clone().map(Bearer);

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Err(StatusCode::FORBIDDEN);
    }
    let doc_id = Uuid::parse_str(parts[0]).map_err(|_| StatusCode::FORBIDDEN)?;

    let mut actor = auth::resolve_actor_from_parts(&ctx, bearer, share_token.as_deref()).await;
    if actor.is_none() {
        if let Some(token_str) = bearer_token {
            actor = auth::resolve_actor_from_token_str(&ctx, &token_str).await;
        }
    }
    let actor = actor.unwrap_or(access::Actor::Public);
    let attachment_path = parts[1..].join("/");
    let payload = ctx
        .file_service()
        .serve_upload(&actor, doc_id, &attachment_path)
        .await
        .map_err(super::types::map_file_error)?;

    Ok(file_payload_response(payload))
}
