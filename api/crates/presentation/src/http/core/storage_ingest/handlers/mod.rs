use axum::{Json, extract::State, http::StatusCode};

use crate::context::CoreContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::dtos::storage_ingest::{IngestBatch, IngestEvent};

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
    let snapshot = auth.permissions.to_vec();
    let batch = IngestBatch {
        events: body
            .events
            .into_iter()
            .map(|event| IngestEvent {
                repo_path: event.repo_path,
                kind: event.kind.into(),
                backend: event.backend,
                content_hash: event.content_hash,
                payload: event.payload,
            })
            .collect(),
    };

    let count = ctx
        .storage_ingest_enqueuer()
        .enqueue_batch(
            auth.workspace_id,
            auth.user_id,
            Some(auth.user_id),
            &snapshot,
            batch,
        )
        .await
        .map_err(|err| {
            crate::http::error::map_service_error(err, "storage_ingest_enqueue_error")
        })?;

    tracing::info!(
        user_id = %auth.user_id,
        events = count,
        "storage_ingest_events_enqueued"
    );
    Ok(StatusCode::ACCEPTED)
}
