use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use crate::context::CoreContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
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
    State(ctx): State<CoreContext>,
    auth: WorkspaceAuth,
    Json(body): Json<IngestBatchRequest>,
) -> Result<StatusCode, ApiError> {
    let queue = ctx.storage_ingest_queue();
    let snapshot = auth.permissions.to_vec();
    enqueue_batch(
        queue.as_ref(),
        auth.workspace_id,
        auth.user_id,
        &snapshot,
        &body,
    )
    .await
    .map(|count| {
        tracing::info!(
            user_id = %auth.user_id,
            events = count,
            "storage_ingest_events_enqueued"
        );
        StatusCode::ACCEPTED
    })
    .map_err(|err| {
        tracing::error!(error = ?err, "storage_ingest_enqueue_failed");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
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
