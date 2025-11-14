use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info, warn};

use crate::application::ports::storage_ingest_queue::{StorageIngestEvent, StorageIngestQueue};
use crate::application::services::storage_ingest::StorageIngestHandler;

pub struct LoggingStorageIngestHandler;

#[async_trait]
impl StorageIngestHandler for LoggingStorageIngestHandler {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()> {
        info!(
            user_id = %event.user_id,
            repo_path = event.repo_path,
            backend = event.backend,
            kind = ?event.kind,
            "storage_ingest_event_received"
        );
        Ok(())
    }
}

pub struct StorageIngestWorker {
    queue: Arc<dyn StorageIngestQueue>,
    handler: Arc<dyn StorageIngestHandler>,
    idle_backoff: Duration,
}

impl StorageIngestWorker {
    pub fn new(queue: Arc<dyn StorageIngestQueue>, handler: Arc<dyn StorageIngestHandler>) -> Self {
        Self {
            queue,
            handler,
            idle_backoff: Duration::from_millis(500),
        }
    }

    pub fn with_idle_backoff(mut self, backoff: Duration) -> Self {
        self.idle_backoff = backoff;
        self
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            match self.queue.fetch_next_event().await {
                Ok(Some(evt)) => {
                    if let Err(err) = self.process_event(evt).await {
                        error!(error = ?err, "storage_ingest_event_failed");
                    }
                    continue;
                }
                Ok(None) => {
                    tokio::time::sleep(self.idle_backoff).await;
                }
                Err(err) => {
                    error!(error = ?err, "storage_ingest_fetch_failed");
                    tokio::time::sleep(self.idle_backoff).await;
                }
            }
        }
    }

    async fn process_event(&self, event: StorageIngestEvent) -> anyhow::Result<()> {
        match self.handler.handle_event(&event).await {
            Ok(()) => {
                self.queue.complete_event(event.id).await?;
                Ok(())
            }
            Err(err) => {
                self.queue.fail_event(event.id, &format!("{err:#}")).await?;
                warn!(error = ?err, "storage_ingest_handler_failed");
                Ok(())
            }
        }
    }
}
