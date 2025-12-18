use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::documents::ports::document_snapshot_archive_repository::{
    DocumentSnapshotArchiveRepository, SnapshotArchiveEntry, SnapshotArchiveInsert,
    SnapshotArchiveRecord,
};

pub struct SqlxDocumentSnapshotArchiveRepository {
    pool: PgPool,
}

impl SqlxDocumentSnapshotArchiveRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocumentSnapshotArchiveRepository for SqlxDocumentSnapshotArchiveRepository {
    async fn insert(
        &self,
        input: SnapshotArchiveInsert<'_>,
    ) -> anyhow::Result<SnapshotArchiveRecord> {
        let inserted = sqlx::query(
            r#"INSERT INTO document_snapshot_archives (
                    document_id,
                    version,
                    snapshot,
                    label,
                    notes,
                    kind,
                    created_by,
                    byte_size,
                    content_hash
                )
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT (document_id, version) DO NOTHING
                RETURNING
                    id,
                    document_id,
                    version,
                    label,
                    notes,
                    kind,
                    created_at,
                    created_by,
                    byte_size,
                    content_hash"#,
        )
        .bind(input.document_id)
        .bind(input.version as i32)
        .bind(input.snapshot)
        .bind(input.label)
        .bind(input.notes)
        .bind(input.kind)
        .bind(input.created_by)
        .bind(input.byte_size)
        .bind(input.content_hash)
        .fetch_optional(&self.pool)
        .await?;

        let row = match inserted {
            Some(row) => row,
            None => {
                sqlx::query(
                    r#"SELECT
                            id,
                            document_id,
                            version,
                            label,
                            notes,
                            kind,
                            created_at,
                            created_by,
                            byte_size,
                            content_hash
                       FROM document_snapshot_archives
                       WHERE document_id = $1 AND version = $2"#,
                )
                .bind(input.document_id)
                .bind(input.version as i32)
                .fetch_one(&self.pool)
                .await?
            }
        };

        Ok(SnapshotArchiveRecord {
            id: row.get("id"),
            document_id: row.get("document_id"),
            version: row.get::<i32, _>("version") as i64,
            label: row.get("label"),
            notes: row.try_get("notes").ok(),
            kind: row.get("kind"),
            created_at: row.get("created_at"),
            created_by: row.try_get("created_by").ok(),
            byte_size: row.get("byte_size"),
            content_hash: row.get("content_hash"),
        })
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<SnapshotArchiveEntry>> {
        let row = sqlx::query(
            r#"SELECT
                    id,
                    document_id,
                    version,
                    snapshot,
                    label,
                    notes,
                    kind,
                    created_at,
                    created_by,
                    byte_size,
                    content_hash
               FROM document_snapshot_archives
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| SnapshotArchiveEntry {
            record: SnapshotArchiveRecord {
                id: row.get("id"),
                document_id: row.get("document_id"),
                version: row.get::<i32, _>("version") as i64,
                label: row.get("label"),
                notes: row.try_get("notes").ok(),
                kind: row.get("kind"),
                created_at: row.get("created_at"),
                created_by: row.try_get("created_by").ok(),
                byte_size: row.get("byte_size"),
                content_hash: row.get("content_hash"),
            },
            bytes: row.get("snapshot"),
        }))
    }

    async fn list_for_document(
        &self,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<SnapshotArchiveRecord>> {
        let rows = sqlx::query(
            r#"SELECT
                    id,
                    document_id,
                    version,
                    label,
                    notes,
                    kind,
                    created_at,
                    created_by,
                    byte_size,
                    content_hash
               FROM document_snapshot_archives
               WHERE document_id = $1
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(doc_id)
        .bind(limit.max(1))
        .bind(offset.max(0))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| SnapshotArchiveRecord {
                id: row.get("id"),
                document_id: row.get("document_id"),
                version: row.get::<i32, _>("version") as i64,
                label: row.get("label"),
                notes: row.try_get("notes").ok(),
                kind: row.get("kind"),
                created_at: row.get("created_at"),
                created_by: row.try_get("created_by").ok(),
                byte_size: row.get("byte_size"),
                content_hash: row.get("content_hash"),
            })
            .collect())
    }

    async fn latest_before(
        &self,
        doc_id: Uuid,
        version: i64,
    ) -> anyhow::Result<Option<SnapshotArchiveEntry>> {
        let row = sqlx::query(
            r#"SELECT
                    id,
                    document_id,
                    version,
                    snapshot,
                    label,
                    notes,
                    kind,
                    created_at,
                    created_by,
                    byte_size,
                    content_hash
               FROM document_snapshot_archives
               WHERE document_id = $1 AND version < $2
               ORDER BY version DESC
               LIMIT 1"#,
        )
        .bind(doc_id)
        .bind(version as i32)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| SnapshotArchiveEntry {
            record: SnapshotArchiveRecord {
                id: row.get("id"),
                document_id: row.get("document_id"),
                version: row.get::<i32, _>("version") as i64,
                label: row.get("label"),
                notes: row.try_get("notes").ok(),
                kind: row.get("kind"),
                created_at: row.get("created_at"),
                created_by: row.try_get("created_by").ok(),
                byte_size: row.get("byte_size"),
                content_hash: row.get("content_hash"),
            },
            bytes: row.get("snapshot"),
        }))
    }
}
