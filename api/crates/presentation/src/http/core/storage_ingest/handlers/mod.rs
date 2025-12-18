use axum::{Json, extract::State, http::HeaderMap};
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use application::core::ports::storage::storage_ingest_queue::StorageIngestQueue;
use application::core::services::storage::ingest::normalize_repo_path;
use domain::storage::ingest_backend::StorageIngestBackend;

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
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await
    .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
    let permissions = workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id)
        .await
        .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
    let queue = ctx.storage_ingest_queue();
    let snapshot = permissions.to_vec();
    enqueue_batch(queue.as_ref(), workspace_id, user_id, &snapshot, &body)
        .await
        .map(|count| {
            tracing::info!(user_id = %user_id, events = count, "storage_ingest_events_enqueued");
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
        let backend = StorageIngestBackend::parse(event.backend.as_deref().unwrap_or("api"));
        queue
            .enqueue_event(
                workspace_id,
                actor_id,
                Some(actor_id),
                &clean_repo,
                backend,
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
