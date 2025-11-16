use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use sqlx::{Row, pool::PoolConnection, postgres::Postgres};
use tracing::{error, info, warn};

use crate::application::services::doc_events::{DocEventRecord, DocEventSubscriber};
use crate::infrastructure::db::PgPool;

pub struct DocEventPoller {
    pool: PgPool,
    subscriber: Arc<dyn DocEventSubscriber>,
    poll_interval: Duration,
    batch_size: i64,
    consumer: String,
}

const DOC_EVENT_POLL_LOCK_KEY: i64 = 0x646f635f65766e74; // "doc_evnt" in hex

impl DocEventPoller {
    pub fn new(
        pool: PgPool,
        subscriber: Arc<dyn DocEventSubscriber>,
        poll_interval: Duration,
        batch_size: i64,
        consumer: &str,
    ) -> Self {
        Self {
            pool,
            subscriber,
            poll_interval,
            batch_size,
            consumer: consumer.to_string(),
        }
    }

    async fn load_cursor(&self) -> anyhow::Result<i64> {
        let value = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_event_id FROM doc_event_cursors WHERE consumer = $1",
        )
        .bind(&self.consumer)
        .fetch_optional(&self.pool)
        .await?
        .flatten()
        .unwrap_or(0);
        Ok(value)
    }

    async fn persist_cursor(&self, cursor: i64) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO doc_event_cursors (consumer, last_event_id)
            VALUES ($1, $2)
            ON CONFLICT (consumer)
            DO UPDATE SET last_event_id = EXCLUDED.last_event_id,
                          updated_at = now()
            "#,
        )
        .bind(&self.consumer)
        .bind(cursor)
        .execute(&self.pool)
        .await?;
        Ok(())
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

    async fn acquire_cluster_lock(&self) -> anyhow::Result<PoolConnection<Postgres>> {
        loop {
            let mut conn = self.pool.acquire().await?;
            let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(DOC_EVENT_POLL_LOCK_KEY)
                .fetch_one(&mut *conn)
                .await?;
            if locked {
                info!(
                    consumer = self.consumer.as_str(),
                    "doc_event_poller_lock_acquired"
                );
                return Ok(conn);
            }
            drop(conn);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn run(self: Arc<Self>) {
        let _lock_guard = match self.acquire_cluster_lock().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(error = ?err, "doc_event_poller_lock_failed");
                return;
            }
        };
        let mut cursor = match self.load_cursor().await {
            Ok(id) => id,
            Err(err) => {
                error!(error = ?err, "doc_event_poller_init_failed");
                0
            }
        };

        'outer: loop {
            match self.fetch_after(cursor).await {
                Ok(events) if !events.is_empty() => {
                    for evt in events {
                        if let Err(err) = self.subscriber.handle_event(&evt).await {
                            warn!(
                                error = ?err,
                                event_id = evt.id,
                                "doc_event_subscriber_failed_retry"
                            );
                            tokio::time::sleep(self.poll_interval).await;
                            continue 'outer;
                        }
                        let new_cursor = evt.id;
                        if let Err(err) = self.persist_cursor(new_cursor).await {
                            error!(
                                error = ?err,
                                event_id = evt.id,
                                "doc_event_cursor_persist_failed"
                            );
                            tokio::time::sleep(self.poll_interval).await;
                            continue 'outer;
                        }
                        cursor = new_cursor;
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
