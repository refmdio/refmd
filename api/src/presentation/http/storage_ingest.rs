use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use crate::application::services::storage_ingest::normalize_repo_path;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct IngestBatchRequest {
    pub events: Vec<IngestEventRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IngestKindParam {
    Upsert,
    Delete,
}

impl From<IngestKindParam> for StorageIngestKind {
    fn from(value: IngestKindParam) -> Self {
        match value {
            IngestKindParam::Upsert => StorageIngestKind::Upsert,
            IngestKindParam::Delete => StorageIngestKind::Delete,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct IngestEventRequest {
    pub repo_path: String,
    pub kind: IngestKindParam,
    pub backend: Option<String>,
    pub content_hash: Option<String>,
    pub payload: Option<Value>,
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/storage/ingest", post(enqueue_ingest_events))
        .with_state(ctx)
}

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
    Json(body): Json<IngestBatchRequest>,
) -> Result<axum::http::StatusCode, axum::http::StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer)
        .await?
        .parse::<Uuid>()
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    let queue = ctx.storage_ingest_queue();
    enqueue_batch(queue.as_ref(), sub, &body)
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
    user_id: Uuid,
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
                user_id,
                &clean_repo,
                event.backend.as_deref().unwrap_or("api"),
                event.kind.clone().into(),
                event.content_hash.as_deref(),
                event.payload.clone(),
            )
            .await?;
        processed += 1;
    }
    Ok(processed)
}
