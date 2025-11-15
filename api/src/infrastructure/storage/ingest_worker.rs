use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info, warn};

use crate::application::ports::storage_ingest_queue::{StorageIngestEvent, StorageIngestQueue};
use crate::application::services::metrics::MetricsRegistry;
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
    metrics: Arc<MetricsRegistry>,
}

impl StorageIngestWorker {
    pub fn new(
        queue: Arc<dyn StorageIngestQueue>,
        handler: Arc<dyn StorageIngestHandler>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            queue,
            handler,
            idle_backoff: Duration::from_millis(500),
            metrics,
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
                self.queue.complete_event(event.id, event.locked_at).await?;
                self.metrics.inc_storage_ingest_success();
                Ok(())
            }
            Err(err) => {
                self.queue
                    .fail_event(event.id, event.locked_at, &format!("{err:#}"))
                    .await?;
                self.metrics.inc_storage_ingest_failure();
                self.metrics.inc_storage_ingest_retry();
                warn!(error = ?err, "storage_ingest_handler_failed");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Mutex;
    use uuid::Uuid;
    use crate::application::ports::storage_ingest_queue::StorageIngestKind;

    #[derive(Default)]
    struct MockQueue {
        completed: Mutex<Vec<i64>>,
        failed: Mutex<Vec<i64>>,
    }

    impl MockQueue {
        fn completed(&self) -> Vec<i64> {
            self.completed.lock().unwrap().clone()
        }

        fn failed(&self) -> Vec<i64> {
            self.failed.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl StorageIngestQueue for MockQueue {
        async fn enqueue_event(
            &self,
            _user_id: Uuid,
            _repo_path: &str,
            _backend: &str,
            _kind: StorageIngestKind,
            _content_hash: Option<&str>,
            _payload: Option<serde_json::Value>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn fetch_next_event(&self) -> anyhow::Result<Option<StorageIngestEvent>> {
            Ok(None)
        }

        async fn complete_event(
            &self,
            event_id: i64,
            _locked_at: chrono::DateTime<Utc>,
        ) -> anyhow::Result<()> {
            self.completed.lock().unwrap().push(event_id);
            Ok(())
        }

        async fn fail_event(
            &self,
            event_id: i64,
            _locked_at: chrono::DateTime<Utc>,
            _error: &str,
        ) -> anyhow::Result<()> {
            self.failed.lock().unwrap().push(event_id);
            Ok(())
        }

        async fn stats(
            &self,
        ) -> anyhow::Result<crate::application::ports::storage_ingest_queue::StorageIngestQueueStats>
        {
            unimplemented!()
        }
    }

    struct StubHandler {
        fail: bool,
    }

    #[async_trait]
    impl StorageIngestHandler for StubHandler {
        async fn handle_event(&self, _event: &StorageIngestEvent) -> anyhow::Result<()> {
            if self.fail {
                Err(anyhow::anyhow!("boom"))
            } else {
                Ok(())
            }
        }
    }

    fn sample_event(id: i64) -> StorageIngestEvent {
        StorageIngestEvent {
            id,
            user_id: Uuid::new_v4(),
            repo_path: "docs/foo.md".into(),
            backend: "fs".into(),
            kind: StorageIngestKind::Upsert,
            content_hash: None,
            payload: None,
            attempts: 0,
            locked_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn successful_event_increments_metrics() {
        let queue = Arc::new(MockQueue::default());
        let handler = Arc::new(StubHandler { fail: false });
        let metrics = Arc::new(MetricsRegistry::default());
        let worker = StorageIngestWorker::new(queue.clone(), handler, metrics.clone());
        worker.process_event(sample_event(1)).await.unwrap();
        assert_eq!(queue.completed(), vec![1]);
        assert_eq!(metrics.snapshot().storage_ingest_success, 1);
    }

    #[tokio::test]
    async fn failing_event_marks_retry_and_metrics() {
        let queue = Arc::new(MockQueue::default());
        let handler = Arc::new(StubHandler { fail: true });
        let metrics = Arc::new(MetricsRegistry::default());
        let worker = StorageIngestWorker::new(queue.clone(), handler, metrics.clone());
        worker.process_event(sample_event(2)).await.unwrap();
        assert_eq!(queue.failed(), vec![2]);
        let snap = metrics.snapshot();
        assert_eq!(snap.storage_ingest_retry, 1);
        assert_eq!(snap.storage_ingest_failure, 1);
    }
}
