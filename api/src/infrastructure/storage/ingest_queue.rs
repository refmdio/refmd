use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::storage_ingest_queue::{
    StorageIngestEvent, StorageIngestKind, StorageIngestQueue, StorageIngestQueueStats,
};
use crate::infrastructure::db::PgPool;

pub struct PgStorageIngestQueue {
    pool: PgPool,
}

impl PgStorageIngestQueue {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn kind_to_str(kind: StorageIngestKind) -> &'static str {
        match kind {
            StorageIngestKind::Upsert => "upsert",
            StorageIngestKind::Delete => "delete",
        }
    }

    fn str_to_kind(raw: &str) -> anyhow::Result<StorageIngestKind> {
        match raw {
            "upsert" => Ok(StorageIngestKind::Upsert),
            "delete" => Ok(StorageIngestKind::Delete),
            _ => anyhow::bail!("unsupported_storage_ingest_kind {raw}"),
        }
    }
}

#[async_trait]
impl StorageIngestQueue for PgStorageIngestQueue {
    async fn enqueue_event(
        &self,
        user_id: Uuid,
        repo_path: &str,
        backend: &str,
        kind: StorageIngestKind,
        content_hash: Option<&str>,
        payload: Option<Value>,
    ) -> anyhow::Result<()> {
        let kind_str = Self::kind_to_str(kind);
        sqlx::query(
            r#"
            INSERT INTO storage_ingest_queue (user_id, repo_path, backend, event_kind, content_hash, payload, attempts, locked_at)
            VALUES ($1, $2, $3, $4, $5, $6, 0, NULL)
            ON CONFLICT ON CONSTRAINT storage_ingest_queue_user_repo_backend_unique
            DO UPDATE SET event_kind = EXCLUDED.event_kind,
                          content_hash = EXCLUDED.content_hash,
                          payload = CASE
                              WHEN EXCLUDED.event_kind = 'upsert' THEN
                                  CASE
                                      WHEN COALESCE(EXCLUDED.payload ? 'previous_path', false) THEN EXCLUDED.payload
                                      WHEN storage_ingest_queue.payload IS NOT NULL
                                           AND storage_ingest_queue.payload ? 'previous_path' THEN
                                          jsonb_set(
                                              COALESCE(EXCLUDED.payload, '{}'::jsonb),
                                              '{previous_path}',
                                              storage_ingest_queue.payload->'previous_path',
                                              true
                                          )
                                      ELSE EXCLUDED.payload
                                  END
                              ELSE EXCLUDED.payload
                          END,
                          attempts = CASE
                              WHEN storage_ingest_queue.locked_at IS NULL THEN 0
                              ELSE storage_ingest_queue.attempts
                          END,
                          locked_at = CASE
                              WHEN storage_ingest_queue.locked_at IS NULL THEN NULL
                              ELSE storage_ingest_queue.locked_at
                          END,
                          pending_retry = CASE
                              WHEN storage_ingest_queue.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          created_at = CASE
                              WHEN storage_ingest_queue.locked_at IS NULL THEN now()
                              ELSE storage_ingest_queue.created_at
                          END
            "#,
        )
        .bind(user_id)
        .bind(repo_path)
        .bind(backend)
        .bind(kind_str)
        .bind(content_hash)
        .bind(payload)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fetch_next_event(&self) -> anyhow::Result<Option<StorageIngestEvent>> {
        let row = sqlx::query(
            r#"
            WITH next_event AS (
                SELECT id FROM storage_ingest_queue
                WHERE locked_at IS NULL
                   OR locked_at < now() - interval '30 seconds'
                ORDER BY created_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE storage_ingest_queue q
            SET locked_at = now(),
                attempts = attempts + 1
            WHERE q.id IN (SELECT id FROM next_event)
            RETURNING q.*
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let kind: String = row.get("event_kind");
        let kind = Self::str_to_kind(&kind)?;

        let locked_at: DateTime<Utc> = row.get("locked_at");

        Ok(Some(StorageIngestEvent {
            id: row.get("id"),
            user_id: row.get("user_id"),
            repo_path: row.get("repo_path"),
            backend: row.get("backend"),
            kind,
            content_hash: row.try_get("content_hash").ok(),
            payload: row.try_get::<Option<Value>, _>("payload").unwrap_or(None),
            attempts: row.try_get("attempts").unwrap_or_default(),
            locked_at,
        }))
    }

    async fn complete_event(&self, event_id: i64, locked_at: DateTime<Utc>) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE storage_ingest_queue
            SET locked_at = NULL,
                attempts = 0,
                pending_retry = false
            WHERE id = $1 AND locked_at = $2 AND pending_retry = true
            "#,
        )
        .bind(event_id)
        .bind(locked_at)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "DELETE FROM storage_ingest_queue WHERE id = $1 AND locked_at = $2 AND pending_retry = false",
            )
            .bind(event_id)
            .bind(locked_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn fail_event(
        &self,
        event_id: i64,
        locked_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE storage_ingest_queue
            SET locked_at = NULL,
                attempts = attempts,
                payload = jsonb_set(
                    coalesce(payload, '{}'::jsonb),
                    '{last_error}',
                    to_jsonb($2::text),
                    true
                ),
                pending_retry = false
            WHERE id = $1 AND locked_at = $3
            "#,
        )
        .bind(event_id)
        .bind(error)
        .bind(locked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn stats(&self) -> anyhow::Result<StorageIngestQueueStats> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE locked_at IS NULL) AS pending,
                COUNT(*) FILTER (WHERE locked_at IS NOT NULL) AS locked,
                COUNT(DISTINCT user_id) AS distinct_users,
                MIN(created_at) FILTER (WHERE locked_at IS NULL) AS oldest_created_at
            FROM storage_ingest_queue
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(StorageIngestQueueStats {
            pending: row.try_get("pending").unwrap_or(0),
            locked: row.try_get("locked").unwrap_or(0),
            distinct_users: row.try_get("distinct_users").unwrap_or(0),
            oldest_created_at: row.try_get("oldest_created_at").ok(),
        })
    }
}
