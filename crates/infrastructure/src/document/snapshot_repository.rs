//! PostgreSQL document snapshot repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{DocumentId, DocumentSnapshot, DocumentSnapshotRepository};
use domain::encryption::DeviceId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL document snapshot repository
#[derive(Clone)]
pub struct PgDocumentSnapshotRepository {
    pool: PgPool,
}

impl PgDocumentSnapshotRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentSnapshotRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct DocumentSnapshotRow {
    id: i64,
    document_id: Uuid,
    version: i64,
    snapshot_data: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i32,
    signature: Vec<u8>,
    author_device_id: Uuid,
    seq_at_snapshot: i64,
    created_at: DateTime<Utc>,
}

impl From<DocumentSnapshotRow> for DocumentSnapshot {
    fn from(row: DocumentSnapshotRow) -> Self {
        Self {
            id: row.id,
            document_id: DocumentId::from_uuid(row.document_id),
            version: row.version,
            snapshot_data: row.snapshot_data,
            nonce: row.nonce,
            key_version: row.key_version,
            signature: row.signature,
            author_device_id: DeviceId::from_uuid(row.author_device_id),
            seq_at_snapshot: row.seq_at_snapshot,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DocumentSnapshotRepository for PgDocumentSnapshotRepository {
    type Error = PgDocumentSnapshotRepositoryError;

    async fn find_by_id(&self, id: i64) -> Result<Option<DocumentSnapshot>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentSnapshotRow>(
            r#"
            SELECT id, document_id, version, snapshot_data, nonce, key_version,
                   signature, author_device_id, seq_at_snapshot, created_at
            FROM document_snapshots
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentSnapshot::from))
    }

    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentSnapshot>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentSnapshotRow>(
            r#"
            SELECT id, document_id, version, snapshot_data, nonce, key_version,
                   signature, author_device_id, seq_at_snapshot, created_at
            FROM document_snapshots
            WHERE document_id = $1
            ORDER BY version DESC
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentSnapshot::from).collect())
    }

    async fn find_latest_by_document_id(&self, document_id: DocumentId) -> Result<Option<DocumentSnapshot>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentSnapshotRow>(
            r#"
            SELECT id, document_id, version, snapshot_data, nonce, key_version,
                   signature, author_device_id, seq_at_snapshot, created_at
            FROM document_snapshots
            WHERE document_id = $1
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentSnapshot::from))
    }

    async fn save(&self, snapshot: &DocumentSnapshot) -> Result<i64, Self::Error> {
        let id = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO document_snapshots (
                document_id, version, snapshot_data, nonce, key_version,
                signature, author_device_id, seq_at_snapshot, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(snapshot.document_id.as_uuid())
        .bind(snapshot.version)
        .bind(&snapshot.snapshot_data)
        .bind(&snapshot.nonce)
        .bind(snapshot.key_version)
        .bind(&snapshot.signature)
        .bind(snapshot.author_device_id.as_uuid())
        .bind(snapshot.seq_at_snapshot)
        .bind(snapshot.created_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_snapshots WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
