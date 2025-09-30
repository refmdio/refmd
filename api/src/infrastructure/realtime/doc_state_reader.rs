use anyhow::Context;
use async_trait::async_trait;
use futures_util::TryStreamExt;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::realtime_hydration_port::{
    DocSnapshot, DocStateReader, DocUpdate, DocumentRecord,
};
use crate::infrastructure::db::PgPool;

#[derive(Clone)]
pub struct SqlxDocStateReader {
    pool: PgPool,
}

impl SqlxDocStateReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocStateReader for SqlxDocStateReader {
    async fn latest_snapshot(&self, doc_id: &Uuid) -> anyhow::Result<Option<DocSnapshot>> {
        let row = sqlx::query(
            "SELECT version, snapshot FROM document_snapshots WHERE document_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let version: i32 = row.get("version");
            let snapshot = row
                .try_get::<Vec<u8>, _>("snapshot")
                .context("doc_snapshot_missing")?;
            Ok(Some(DocSnapshot {
                version: version as i64,
                snapshot,
            }))
        } else {
            Ok(None)
        }
    }

    async fn updates_since(&self, doc_id: &Uuid, from_seq: i64) -> anyhow::Result<Vec<DocUpdate>> {
        let mut rows = sqlx::query(
            "SELECT seq, update FROM document_updates WHERE document_id = $1 AND seq > $2 ORDER BY seq ASC",
        )
        .bind(doc_id)
        .bind(from_seq)
        .fetch(&self.pool);

        let mut result = Vec::new();
        while let Some(row) = rows.try_next().await? {
            let seq: i64 = row.get("seq");
            let update = row
                .try_get::<Vec<u8>, _>("update")
                .context("doc_update_missing")?;
            result.push(DocUpdate { seq, update });
        }
        Ok(result)
    }

    async fn document_record(&self, doc_id: &Uuid) -> anyhow::Result<Option<DocumentRecord>> {
        let row = sqlx::query("SELECT type, path, title, owner_id FROM documents WHERE id = $1")
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|row| DocumentRecord {
            doc_type: row.get("type"),
            path: row.try_get("path").ok(),
            title: row.get("title"),
            owner_id: row.try_get("owner_id").ok(),
        }))
    }
}
