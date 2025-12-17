use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use application::core::ports::storage::storage_projection_queue::{
    StorageProjectionJob, StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::core::db::PgPool;

pub struct PgStorageProjectionQueue {
    pool: PgPool,
}

impl PgStorageProjectionQueue {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn kind_to_str(kind: StorageProjectionJobKind) -> &'static str {
        match kind {
            StorageProjectionJobKind::DocSync => "doc_sync",
            StorageProjectionJobKind::FolderSync => "folder_sync",
            StorageProjectionJobKind::DeleteDoc => "delete_doc",
            StorageProjectionJobKind::DeleteFolder => "delete_folder",
        }
    }

    fn str_to_kind(raw: &str) -> anyhow::Result<StorageProjectionJobKind> {
        match raw {
            "doc_sync" => Ok(StorageProjectionJobKind::DocSync),
            "folder_sync" => Ok(StorageProjectionJobKind::FolderSync),
            "delete_doc" => Ok(StorageProjectionJobKind::DeleteDoc),
            "delete_folder" => Ok(StorageProjectionJobKind::DeleteFolder),
            _ => anyhow::bail!("unsupported_storage_projection_job_type {raw}"),
        }
    }
}

#[async_trait]
impl StorageProjectionQueue for PgStorageProjectionQueue {
    async fn enqueue_doc_job(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        match kind {
            StorageProjectionJobKind::DocSync | StorageProjectionJobKind::DeleteDoc => {}
            other => anyhow::bail!("job_kind {other:?} requires a folder_id"),
        }

        let job_type = Self::kind_to_str(kind);
        sqlx::query(
            r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, doc_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, doc_id) WHERE doc_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(job_type)
        .bind(doc_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn enqueue_doc_job_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        match kind {
            StorageProjectionJobKind::DocSync | StorageProjectionJobKind::DeleteDoc => {}
            other => anyhow::bail!("job_kind {other:?} requires a folder_id"),
        }

        let job_type = Self::kind_to_str(kind);
        sqlx::query(
            r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, doc_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, doc_id) WHERE doc_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(job_type)
        .bind(doc_id)
        .bind(reason)
        .execute(tx.as_mut())
        .await?;
        Ok(())
    }

    async fn enqueue_folder_job(
        &self,
        workspace_id: Uuid,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        match kind {
            StorageProjectionJobKind::FolderSync | StorageProjectionJobKind::DeleteFolder => {}
            other => anyhow::bail!("job_kind {other:?} requires a doc_id"),
        }

        let job_type = Self::kind_to_str(kind);
        sqlx::query(
            r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, folder_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, folder_id) WHERE folder_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(job_type)
        .bind(folder_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn enqueue_folder_job_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        match kind {
            StorageProjectionJobKind::FolderSync | StorageProjectionJobKind::DeleteFolder => {}
            other => anyhow::bail!("job_kind {other:?} requires a doc_id"),
        }

        let job_type = Self::kind_to_str(kind);
        sqlx::query(
            r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, folder_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, folder_id) WHERE folder_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(job_type)
        .bind(folder_id)
        .bind(reason)
        .execute(tx.as_mut())
        .await?;
        Ok(())
    }

    async fn fetch_next_job(
        &self,
        lock_timeout_secs: i64,
    ) -> anyhow::Result<Option<StorageProjectionJob>> {
        let row = sqlx::query(
            r#"
            WITH next_job AS (
                SELECT id FROM storage_projection_jobs
                WHERE locked_at IS NULL
                   OR locked_at < now() - ($1 * interval '1 second')
                ORDER BY created_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE storage_projection_jobs j
            SET locked_at = now(),
                attempts = attempts + 1,
                updated_at = now()
            WHERE j.id IN (SELECT id FROM next_job)
            RETURNING j.id, j.workspace_id, j.job_type, j.doc_id, j.folder_id, j.reason, j.attempts, j.locked_at
            "#,
        )
        .bind(lock_timeout_secs.max(1))
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let job_type: String = row.get("job_type");
        let kind = Self::str_to_kind(&job_type)?;

        Ok(Some(StorageProjectionJob {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            job_type: kind,
            doc_id: row.try_get::<Option<Uuid>, _>("doc_id").unwrap_or(None),
            folder_id: row.try_get::<Option<Uuid>, _>("folder_id").unwrap_or(None),
            reason: row.try_get::<Option<String>, _>("reason").unwrap_or(None),
            attempts: row.try_get("attempts").unwrap_or_default(),
            locked_at: row.get::<DateTime<Utc>, _>("locked_at"),
        }))
    }

    async fn complete_job(&self, job_id: i64, locked_at: DateTime<Utc>) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE storage_projection_jobs
            SET locked_at = NULL,
                attempts = 0,
                last_error = NULL,
                pending_retry = false,
                updated_at = now()
            WHERE id = $1 AND locked_at = $2 AND pending_retry = true
            "#,
        )
        .bind(job_id)
        .bind(locked_at)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "DELETE FROM storage_projection_jobs WHERE id = $1 AND locked_at = $2 AND pending_retry = false",
            )
            .bind(job_id)
            .bind(locked_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn fail_job(
        &self,
        job_id: i64,
        locked_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE storage_projection_jobs
            SET last_error = $2,
                locked_at = NULL,
                pending_retry = false,
                updated_at = now()
            WHERE id = $1 AND locked_at = $3
            "#,
        )
        .bind(job_id)
        .bind(error)
        .bind(locked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
