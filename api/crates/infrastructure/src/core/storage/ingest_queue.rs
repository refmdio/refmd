use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::core::ports::storage::storage_ingest_queue::{
    StorageIngestEvent, StorageIngestKind, StorageIngestQueue, StorageIngestQueueStats,
};
use domain::storage::ingest_backend::StorageIngestBackend;

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

fn parse_permission_snapshot(raw: Option<Value>) -> Vec<String> {
    match raw {
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

#[async_trait]
impl StorageIngestQueue for PgStorageIngestQueue {
    async fn enqueue_event(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        repo_path: &str,
        backend: StorageIngestBackend,
        kind: StorageIngestKind,
        content_hash: Option<&str>,
        payload: Option<Value>,
        permission_snapshot: &[String],
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let kind_str = Self::kind_to_str(kind);
            sqlx::query(
                r#"
            INSERT INTO storage_ingest_queue (workspace_id, user_id, actor_id, repo_path, backend, event_kind, content_hash, payload, permission_snapshot, attempts, locked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, NULL)
            ON CONFLICT ON CONSTRAINT storage_ingest_queue_workspace_repo_backend_unique
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
                          actor_id = EXCLUDED.actor_id,
                          permission_snapshot = EXCLUDED.permission_snapshot,
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
            .bind(workspace_id)
            .bind(user_id)
            .bind(actor_id)
            .bind(repo_path)
            .bind(backend.as_str())
            .bind(kind_str)
            .bind(content_hash)
            .bind(payload)
            .bind(json!(permission_snapshot))
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn fetch_next_event(&self) -> PortResult<Option<StorageIngestEvent>> {
        let out: anyhow::Result<Option<StorageIngestEvent>> = async {
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

            let snapshot_value: Option<Value> = row.try_get("permission_snapshot").ok();
            Ok(Some(StorageIngestEvent {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                user_id: row.get("user_id"),
                actor_id: row.try_get("actor_id").ok(),
                repo_path: row.get("repo_path"),
                backend: StorageIngestBackend::parse(&row.get::<String, _>("backend")),
                kind,
                content_hash: row.try_get("content_hash").ok(),
                payload: row.try_get::<Option<Value>, _>("payload").unwrap_or(None),
                attempts: row.try_get("attempts").unwrap_or_default(),
                locked_at,
                permission_snapshot: parse_permission_snapshot(snapshot_value),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn complete_event(&self, event_id: i64, locked_at: DateTime<Utc>) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
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
        .await;
        out.map_err(Into::into)
    }

    async fn fail_event(
        &self,
        event_id: i64,
        locked_at: DateTime<Utc>,
        error: &str,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
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
        .await;
        out.map_err(Into::into)
    }

    async fn stats(&self) -> PortResult<StorageIngestQueueStats> {
        let out: anyhow::Result<StorageIngestQueueStats> = async {
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
        .await;
        out.map_err(Into::into)
    }
}
