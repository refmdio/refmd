use axum::{Json, extract::State, http::HeaderMap};
use uuid::Uuid;

use application::ports::storage_ingest_queue::StorageIngestQueue;
use application::services::storage_ingest::normalize_repo_path;
use crate::context::AppContext;
use crate::http::auth::{self, Bearer};
use crate::http::workspaces::scope as workspace_scope;

use super::types::IngestBatchRequest;

#[utoipa::path(
    post,
    path = "/api/storage/ingest",
    tag = "Storage",
    request_body = IngestBatchRequest,
    responses((status = 202, description = "Events enqueued"), (status = 400, description = "Invalid request")),
)]
pub async fn enqueue_ingest_events(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(body): Json<IngestBatchRequest>,
) -> Result<axum::http::StatusCode, axum::http::StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone()))
        .await?
        .parse::<Uuid>()
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        sub,
    )
    .await
    .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
    let permissions = workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, sub)
        .await
        .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
    let queue = ctx.storage_ingest_queue();
    let snapshot = permissions.to_vec();
    enqueue_batch(queue.as_ref(), workspace_id, sub, &snapshot, &body)
        .await
        .map(|count| {
            tracing::info!(user_id = %sub, events = count, "storage_ingest_events_enqueued");
            axum::http::StatusCode::ACCEPTED
        })
        .map_err(|err| {
            tracing::error!(error = ?err, "storage_ingest_enqueue_failed");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn enqueue_batch(
    queue: &dyn StorageIngestQueue,
    workspace_id: Uuid,
    actor_id: Uuid,
    permission_snapshot: &[String],
    body: &IngestBatchRequest,
) -> anyhow::Result<usize> {
    let mut processed = 0usize;
    for event in &body.events {
        let repo_path = event.repo_path.trim();
        if repo_path.is_empty() {
            continue;
        }
        let Some(clean_repo) = normalize_repo_path(repo_path) else {
            tracing::warn!(repo_path, "storage_ingest_invalid_repo_path_request");
            continue;
        };
        queue
            .enqueue_event(
                workspace_id,
                actor_id,
                Some(actor_id),
                &clean_repo,
                event.backend.as_deref().unwrap_or("api"),
                event.kind.clone().into(),
                event.content_hash.as_deref(),
                event.payload.clone(),
                permission_snapshot,
            )
            .await?;
        processed += 1;
    }
    Ok(processed)
}
