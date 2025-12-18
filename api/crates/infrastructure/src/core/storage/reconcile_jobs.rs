use async_trait::async_trait;
use sqlx::Row;
use tracing::debug;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::storage::storage_reconcile_jobs::{
    StorageReconcileJob, StorageReconcileJobs,
};

pub struct PgStorageReconcileJobs {
    pool: PgPool,
}

impl PgStorageReconcileJobs {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl StorageReconcileJobs for PgStorageReconcileJobs {
    async fn enqueue(&self, workspace_id: Uuid, scope: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO storage_reconcile_jobs (workspace_id, scope, attempts, locked_at, last_error)
            VALUES ($1, $2, 0, NULL, NULL)
            ON CONFLICT ON CONSTRAINT storage_reconcile_jobs_workspace_scope_unique
            DO UPDATE
            SET attempts = CASE
                    WHEN storage_reconcile_jobs.locked_at IS NULL THEN 0
                    ELSE storage_reconcile_jobs.attempts
                END,
                locked_at = CASE
                    WHEN storage_reconcile_jobs.locked_at IS NULL THEN NULL
                    ELSE storage_reconcile_jobs.locked_at
                END,
                last_error = NULL,
                pending_retry = CASE
                    WHEN storage_reconcile_jobs.locked_at IS NULL THEN false
                    ELSE true
                END,
                updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(scope)
        .execute(&self.pool)
        .await?;
        debug!(
            workspace_id = %workspace_id,
            scope,
            "storage_reconcile_job_enqueued"
        );
        Ok(())
    }

    async fn fetch_next(
        &self,
        lock_timeout_secs: i64,
    ) -> anyhow::Result<Option<StorageReconcileJob>> {
        let row = sqlx::query(
            r#"
            WITH next_job AS (
                SELECT id FROM storage_reconcile_jobs
                WHERE locked_at IS NULL
                   OR locked_at < now() - ($1 * interval '1 second')
                ORDER BY created_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE storage_reconcile_jobs j
            SET locked_at = now(),
                attempts = attempts + 1,
                updated_at = now()
            WHERE j.id IN (SELECT id FROM next_job)
            RETURNING j.id, j.workspace_id, j.scope, j.attempts
            "#,
        )
        .bind(lock_timeout_secs.max(1))
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| StorageReconcileJob {
            id: r.get("id"),
            workspace_id: r.get("workspace_id"),
            scope: r.get("scope"),
            attempts: r.get("attempts"),
        }))
    }

    async fn complete(&self, job_id: i64) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE storage_reconcile_jobs
            SET locked_at = NULL,
                attempts = 0,
                pending_retry = false,
                last_error = NULL,
                updated_at = now()
            WHERE id = $1 AND pending_retry = true
            "#,
        )
        .bind(job_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            sqlx::query("DELETE FROM storage_reconcile_jobs WHERE id = $1")
                .bind(job_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE storage_reconcile_jobs
            SET last_error = $2,
                locked_at = NULL,
                pending_retry = false,
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
