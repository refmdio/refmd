use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use sqlx::Row;
use tracing::{error, warn};

use crate::application::services::doc_events::{DocEventRecord, DocEventSubscriber};
use crate::infrastructure::db::PgPool;

pub struct DocEventPoller {
    pool: PgPool,
    subscriber: Arc<dyn DocEventSubscriber>,
    poll_interval: Duration,
    batch_size: i64,
}

impl DocEventPoller {
    pub fn new(
        pool: PgPool,
        subscriber: Arc<dyn DocEventSubscriber>,
        poll_interval: Duration,
        batch_size: i64,
    ) -> Self {
        Self {
            pool,
            subscriber,
            poll_interval,
            batch_size,
        }
    }

    async fn current_max_id(&self) -> anyhow::Result<i64> {
        let id = sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(id) FROM doc_events")
            .fetch_one(&self.pool)
            .await?
            .unwrap_or(0);
        Ok(id)
    }

    async fn fetch_after(&self, last_id: i64) -> anyhow::Result<Vec<DocEventRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, doc_id, event_type, payload
               FROM doc_events
               WHERE id > $1
               ORDER BY id ASC
               LIMIT $2"#,
        )
        .bind(last_id)
        .bind(self.batch_size)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let doc_id = row.try_get("doc_id").ok()?;
                let event_type = row.try_get::<String, _>("event_type").ok()?;
                let payload: Option<Value> = row.try_get("payload").ok();
                Some(DocEventRecord {
                    id: row.get("id"),
                    doc_id,
                    event_type,
                    payload,
                })
            })
            .collect())
    }

    pub async fn run(self: Arc<Self>) {
        let mut cursor = match self.current_max_id().await {
            Ok(id) => id,
            Err(err) => {
                error!(error = ?err, "doc_event_poller_init_failed");
                0
            }
        };

        loop {
            match self.fetch_after(cursor).await {
                Ok(events) if !events.is_empty() => {
                    for evt in events {
                        if let Err(err) = self.subscriber.handle_event(&evt).await {
                            warn!(
                                error = ?err,
                                event_id = evt.id,
                                "doc_event_subscriber_failed"
                            );
                        }
                        cursor = evt.id;
                    }
                }
                Ok(_) => {
                    tokio::time::sleep(self.poll_interval).await;
                }
                Err(err) => {
                    error!(error = ?err, "doc_event_fetch_failed");
                    tokio::time::sleep(self.poll_interval).await;
                }
            }
        }
    }
}
