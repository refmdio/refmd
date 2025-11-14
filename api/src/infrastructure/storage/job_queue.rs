use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    application::ports::storage_projection_queue::{
        StorageProjectionJob, StorageProjectionJobKind, StorageProjectionQueue,
    },
    infrastructure::db::PgPool,
};

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
            INSERT INTO storage_projection_jobs (job_type, doc_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, 0, NULL, NULL)
            ON CONFLICT (job_type, doc_id)
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = NULL,
                          attempts = 0,
                          last_error = NULL,
                          updated_at = now()
            "#,
        )
        .bind(job_type)
        .bind(doc_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn enqueue_folder_job(
        &self,
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
            INSERT INTO storage_projection_jobs (job_type, folder_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, 0, NULL, NULL)
            ON CONFLICT (job_type, folder_id)
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = NULL,
                          attempts = 0,
                          last_error = NULL,
                          updated_at = now()
            "#,
        )
        .bind(job_type)
        .bind(folder_id)
        .bind(reason)
        .execute(&self.pool)
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
            RETURNING j.id, j.job_type, j.doc_id, j.folder_id, j.reason, j.attempts
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
            job_type: kind,
            doc_id: row.try_get::<Option<Uuid>, _>("doc_id").unwrap_or(None),
            folder_id: row.try_get::<Option<Uuid>, _>("folder_id").unwrap_or(None),
            reason: row.try_get::<Option<String>, _>("reason").unwrap_or(None),
            attempts: row.try_get("attempts").unwrap_or_default(),
        }))
    }

    async fn complete_job(&self, job_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM storage_projection_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn fail_job(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE storage_projection_jobs
            SET last_error = $2,
                locked_at = NULL,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
