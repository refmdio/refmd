use anyhow::Context;
use async_trait::async_trait;
use futures_util::TryStreamExt;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::realtime::realtime_hydration_port::{
    DocSnapshot, DocStateReader, DocUpdate, DocumentRecord,
};
use domain::documents::doc_type::DocumentType;

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
    async fn latest_snapshot(&self, doc_id: &Uuid) -> PortResult<Option<DocSnapshot>> {
        let out: anyhow::Result<Option<DocSnapshot>> = async {
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
        .await;
        out.map_err(Into::into)
    }

    async fn updates_since(&self, doc_id: &Uuid, from_seq: i64) -> PortResult<Vec<DocUpdate>> {
        let out: anyhow::Result<Vec<DocUpdate>> = async {
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
        .await;
        out.map_err(Into::into)
    }

    async fn document_record(&self, doc_id: &Uuid) -> PortResult<Option<DocumentRecord>> {
        let out: anyhow::Result<Option<DocumentRecord>> = async {
            let row = sqlx::query(
                "SELECT type, path, desired_path, title, owner_id, workspace_id FROM documents WHERE id = $1",
            )
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;

            row.map(|row| {
                let doc_type_str: String = row.get("type");
                let doc_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                Ok(DocumentRecord {
                    doc_type,
                    path: row.try_get("path").ok(),
                    desired_path: row.try_get("desired_path").ok(),
                    title: row.get("title"),
                    owner_id: row.try_get("owner_id").ok(),
                    workspace_id: row.get("workspace_id"),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }
}
