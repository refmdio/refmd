use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DocEventRecord {
    pub id: i64,
    pub workspace_id: Uuid,
    pub doc_id: Uuid,
    pub event_type: String,
    pub payload: Option<Value>,
}

#[async_trait]
pub trait DocEventSubscriber: Send + Sync {
    async fn handle_event(&self, event: &DocEventRecord) -> anyhow::Result<()>;
}

pub struct LoggingDocEventSubscriber;

impl LoggingDocEventSubscriber {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl DocEventSubscriber for LoggingDocEventSubscriber {
    async fn handle_event(&self, event: &DocEventRecord) -> anyhow::Result<()> {
        info!(
            doc_id = %event.doc_id,
            event_type = event.event_type,
            payload = ?event.payload,
            "doc_event_consumed"
        );
        Ok(())
    }
}

pub struct FanoutDocEventSubscriber {
    subscribers: Vec<Arc<dyn DocEventSubscriber>>,
}

impl FanoutDocEventSubscriber {
    pub fn new(subscribers: Vec<Arc<dyn DocEventSubscriber>>) -> Arc<Self> {
        Arc::new(Self { subscribers })
    }
}

#[async_trait]
impl DocEventSubscriber for FanoutDocEventSubscriber {
    async fn handle_event(&self, event: &DocEventRecord) -> anyhow::Result<()> {
        for sub in &self.subscribers {
            if let Err(err) = sub.handle_event(event).await {
                error!(
                    error = ?err,
                    event_id = event.id,
                    "doc_event_subscriber_failed"
                );
                return Err(err);
            }
        }
        Ok(())
    }
}
