use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::core::dtos::storage_ingest::IngestBatch;
use crate::core::ports::storage::storage_ingest_queue::StorageIngestQueue;
use crate::core::services::errors::ServiceError;
use domain::documents::path::normalize_repo_path;
use domain::storage::ingest_backend::StorageIngestBackend;

pub struct StorageIngestEnqueueService {
    queue: Arc<dyn StorageIngestQueue>,
}

#[async_trait]
pub trait StorageIngestEnqueueServiceFacade: Send + Sync {
    async fn enqueue_batch(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        permission_snapshot: &[String],
        batch: IngestBatch,
    ) -> Result<usize, ServiceError>;
}

#[async_trait]
impl StorageIngestEnqueueServiceFacade for StorageIngestEnqueueService {
    async fn enqueue_batch(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        permission_snapshot: &[String],
        batch: IngestBatch,
    ) -> Result<usize, ServiceError> {
        self.enqueue_batch(workspace_id, user_id, actor_id, permission_snapshot, batch)
            .await
    }
}

impl StorageIngestEnqueueService {
    pub fn new(queue: Arc<dyn StorageIngestQueue>) -> Self {
        Self { queue }
    }

    pub async fn enqueue_batch(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        permission_snapshot: &[String],
        batch: IngestBatch,
    ) -> Result<usize, ServiceError> {
        const MAX_EVENTS: usize = 1024;
        if batch.events.is_empty() {
            return Err(ServiceError::BadRequest("events_required"));
        }
        if batch.events.len() > MAX_EVENTS {
            return Err(ServiceError::BadRequest("too_many_events"));
        }

        let mut processed = 0usize;
        for event in batch.events {
            let repo_path = event.repo_path.trim();
            if repo_path.is_empty() {
                return Err(ServiceError::BadRequest("repo_path_required"));
            }
            let Some(clean_repo) = normalize_repo_path(repo_path) else {
                return Err(ServiceError::BadRequest("invalid_repo_path"));
            };

            let backend = StorageIngestBackend::parse(event.backend.as_deref().unwrap_or("api"));

            self.queue
                .enqueue_event(
                    workspace_id,
                    user_id,
                    actor_id,
                    &clean_repo,
                    backend,
                    event.kind,
                    event.content_hash.as_deref(),
                    event.payload,
                    permission_snapshot,
                )
                .await
                .map_err(ServiceError::from)?;
            processed += 1;
        }

        Ok(processed)
    }
}
