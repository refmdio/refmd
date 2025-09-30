use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::realtime_persistence_port::DocPersistencePort;
use crate::infrastructure::db::PgPool;

#[derive(Clone)]
pub struct SqlxDocPersistenceAdapter {
    pool: PgPool,
}

impl SqlxDocPersistenceAdapter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocPersistencePort for SqlxDocPersistenceAdapter {
    async fn append_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &[u8],
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO document_updates (document_id, seq, update) VALUES ($1, $2, $3)")
            .bind(doc_id)
            .bind(seq)
            .bind(update)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn latest_update_seq(&self, doc_id: &Uuid) -> anyhow::Result<Option<i64>> {
        let row =
            sqlx::query("SELECT MAX(seq) AS max_seq FROM document_updates WHERE document_id = $1")
                .bind(doc_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|row| row.try_get("max_seq").ok()))
    }

    async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        version: i64,
        snapshot: &[u8],
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO document_snapshots (document_id, version, snapshot) VALUES ($1, $2, $3)
             ON CONFLICT (document_id, version) DO UPDATE SET snapshot = EXCLUDED.snapshot",
        )
        .bind(doc_id)
        .bind(version as i32)
        .bind(snapshot)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn latest_snapshot_version(&self, doc_id: &Uuid) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT MAX(version) AS max_version FROM document_snapshots WHERE document_id = $1",
        )
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|row| row.try_get::<i32, _>("max_version").ok().map(|v| v as i64)))
    }

    async fn prune_snapshots(&self, doc_id: &Uuid, keep_latest: i64) -> anyhow::Result<()> {
        sqlx::query(
            "DELETE FROM document_snapshots WHERE document_id = $1 AND version NOT IN (
                SELECT version FROM document_snapshots WHERE document_id = $1 ORDER BY version DESC LIMIT $2
            )",
        )
        .bind(doc_id)
        .bind(keep_latest)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn prune_updates_before(&self, doc_id: &Uuid, seq_inclusive: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM document_updates WHERE document_id = $1 AND seq <= $2")
            .bind(doc_id)
            .bind(seq_inclusive)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn clear_updates(&self, doc_id: &Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
            .bind(doc_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
