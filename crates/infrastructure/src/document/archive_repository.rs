//! PostgreSQL snapshot archive repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{
    ArchiveKind, DocumentId, DocumentSnapshotArchive, SnapshotArchiveId, SnapshotArchiveRepository,
};
use domain::identity::UserId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL snapshot archive repository
#[derive(Clone)]
pub struct PgSnapshotArchiveRepository {
    pool: PgPool,
}

impl PgSnapshotArchiveRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgSnapshotArchiveRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid archive kind: {0}")]
    InvalidArchiveKind(String),
}

#[derive(sqlx::FromRow)]
struct SnapshotArchiveRow {
    id: Uuid,
    document_id: Uuid,
    snapshot_id: i64,
    label: String,
    notes: Option<String>,
    kind: String,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl SnapshotArchiveRow {
    fn try_into_archive(self) -> Result<DocumentSnapshotArchive, PgSnapshotArchiveRepositoryError> {
        let kind: ArchiveKind = self
            .kind
            .parse()
            .map_err(|_| PgSnapshotArchiveRepositoryError::InvalidArchiveKind(self.kind.clone()))?;

        Ok(DocumentSnapshotArchive {
            id: SnapshotArchiveId::from_uuid(self.id),
            document_id: DocumentId::from_uuid(self.document_id),
            snapshot_id: self.snapshot_id,
            label: self.label,
            notes: self.notes,
            kind,
            created_by: self.created_by.map(UserId::from_uuid),
            created_at: self.created_at,
        })
    }
}

#[async_trait]
impl SnapshotArchiveRepository for PgSnapshotArchiveRepository {
    type Error = PgSnapshotArchiveRepositoryError;

    async fn find_by_id(
        &self,
        id: SnapshotArchiveId,
    ) -> Result<Option<DocumentSnapshotArchive>, Self::Error> {
        let row = sqlx::query_as::<_, SnapshotArchiveRow>(
            r#"
            SELECT id, document_id, snapshot_id, label, notes, kind, created_by, created_at
            FROM document_snapshot_archives
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_archive()).transpose()
    }

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentSnapshotArchive>, Self::Error> {
        let rows = sqlx::query_as::<_, SnapshotArchiveRow>(
            r#"
            SELECT id, document_id, snapshot_id, label, notes, kind, created_by, created_at
            FROM document_snapshot_archives
            WHERE document_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_archive()).collect()
    }

    async fn save(&self, archive: &DocumentSnapshotArchive) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO document_snapshot_archives (
                id, document_id, snapshot_id, label, notes, kind, created_by, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                label = EXCLUDED.label,
                notes = EXCLUDED.notes
            "#,
        )
        .bind(archive.id.as_uuid())
        .bind(archive.document_id.as_uuid())
        .bind(archive.snapshot_id)
        .bind(&archive.label)
        .bind(&archive.notes)
        .bind(archive.kind.as_str())
        .bind(archive.created_by.map(|id| id.as_uuid()))
        .bind(archive.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: SnapshotArchiveId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_snapshot_archives WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_snapshot_archives WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
