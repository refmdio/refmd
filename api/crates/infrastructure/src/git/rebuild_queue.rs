use async_trait::async_trait;
use sqlx::Row;
use tracing::debug;
use uuid::Uuid;

use application::ports::git_rebuild_job_queue::{GitRebuildJob, GitRebuildJobQueue};
use crate::db::PgPool;

pub struct PgGitRebuildJobQueue {
    pool: PgPool,
}

impl PgGitRebuildJobQueue {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GitRebuildJobQueue for PgGitRebuildJobQueue {
    async fn enqueue(
        &self,
        workspace_id: Uuid,
        actor_id: Option<Uuid>,
        permission_snapshot: &[String],
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO git_rebuild_jobs (workspace_id, actor_id, permission_snapshot, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, 0, NULL, NULL)
            ON CONFLICT (workspace_id)
            DO UPDATE SET attempts = CASE
                               WHEN git_rebuild_jobs.locked_at IS NULL THEN 0
                               ELSE git_rebuild_jobs.attempts
                           END,
                           locked_at = CASE
                               WHEN git_rebuild_jobs.locked_at IS NULL THEN NULL
                               ELSE git_rebuild_jobs.locked_at
                           END,
                           last_error = NULL,
                           actor_id = EXCLUDED.actor_id,
                           permission_snapshot = EXCLUDED.permission_snapshot,
                           pending_retry = CASE
                               WHEN git_rebuild_jobs.locked_at IS NULL THEN false
                               ELSE true
                           END,
                           updated_at = now()
            "#,
        )
        .bind(workspace_id)
        .bind(actor_id)
        .bind(serde_json::json!(permission_snapshot))
        .execute(&self.pool)
        .await?;
        debug!(workspace_id = %workspace_id, "git_rebuild_job_queued");
        Ok(())
    }

    async fn fetch_next(&self, lock_timeout_secs: i64) -> anyhow::Result<Option<GitRebuildJob>> {
        let row = sqlx::query(
            r#"
            WITH next_job AS (
                SELECT id
                FROM git_rebuild_jobs
                WHERE locked_at IS NULL
                   OR locked_at < now() - ($1 * interval '1 second')
                ORDER BY updated_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE git_rebuild_jobs j
            SET locked_at = now(),
                attempts = attempts + 1,
                updated_at = now()
            WHERE j.id IN (SELECT id FROM next_job)
            RETURNING j.id, j.workspace_id, j.actor_id, j.permission_snapshot, j.attempts
            "#,
        )
        .bind(lock_timeout_secs.max(1))
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| GitRebuildJob {
            id: r.get("id"),
            workspace_id: r.get("workspace_id"),
            actor_id: r.try_get("actor_id").ok(),
            attempts: r.get("attempts"),
            permission_snapshot: parse_permission_snapshot(r.try_get("permission_snapshot").ok()),
        }))
    }

    async fn complete(&self, job_id: i64) -> anyhow::Result<()> {
        let res = sqlx::query(
            r#"
            UPDATE git_rebuild_jobs
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

        if res.rows_affected() == 0 {
            sqlx::query("DELETE FROM git_rebuild_jobs WHERE id = $1")
                .bind(job_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE git_rebuild_jobs
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

fn parse_permission_snapshot(raw: Option<serde_json::Value>) -> Vec<String> {
    match raw {
        Some(serde_json::Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}
