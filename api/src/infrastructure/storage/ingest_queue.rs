use async_trait::async_trait;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::storage_ingest_queue::{
    StorageIngestEvent, StorageIngestKind, StorageIngestQueue,
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
            ON CONFLICT (user_id, repo_path, backend)
            DO UPDATE SET event_kind = EXCLUDED.event_kind,
                          content_hash = EXCLUDED.content_hash,
                          payload = EXCLUDED.payload,
                          attempts = 0,
                          locked_at = NULL,
                          created_at = now()
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

        Ok(Some(StorageIngestEvent {
            id: row.get("id"),
            user_id: row.get("user_id"),
            repo_path: row.get("repo_path"),
            backend: row.get("backend"),
            kind,
            content_hash: row.try_get("content_hash").ok(),
            payload: row.try_get::<Option<Value>, _>("payload").unwrap_or(None),
            attempts: row.try_get("attempts").unwrap_or_default(),
        }))
    }

    async fn complete_event(&self, event_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM storage_ingest_queue WHERE id = $1")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn fail_event(&self, event_id: i64, error: &str) -> anyhow::Result<()> {
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
                )
            WHERE id = $1
            "#,
        )
        .bind(event_id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
