//! PostgreSQL document update repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{DocumentId, DocumentUpdate, DocumentUpdateRepository};
use domain::encryption::DeviceId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL document update repository
#[derive(Clone)]
pub struct PgDocumentUpdateRepository {
    pool: PgPool,
}

impl PgDocumentUpdateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentUpdateRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct DocumentUpdateRow {
    id: i64,
    document_id: Uuid,
    seq: i64,
    update_data: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i32,
    update_hash: String,
    prev_update_hash: Option<String>,
    signature: Vec<u8>,
    author_device_id: Uuid,
    timestamp: i64,
    created_at: DateTime<Utc>,
}

impl From<DocumentUpdateRow> for DocumentUpdate {
    fn from(row: DocumentUpdateRow) -> Self {
        Self {
            id: row.id,
            document_id: DocumentId::from_uuid(row.document_id),
            seq: row.seq,
            update_data: row.update_data,
            nonce: row.nonce,
            key_version: row.key_version,
            update_hash: row.update_hash,
            prev_update_hash: row.prev_update_hash,
            signature: row.signature,
            author_device_id: DeviceId::from_uuid(row.author_device_id),
            timestamp: row.timestamp,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DocumentUpdateRepository for PgDocumentUpdateRepository {
    type Error = PgDocumentUpdateRepositoryError;

    async fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentUpdate>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentUpdateRow>(
            r#"
            SELECT id, document_id, seq, update_data, nonce, key_version, update_hash,
                   prev_update_hash, signature, author_device_id, timestamp, created_at
            FROM document_updates
            WHERE document_id = $1
            ORDER BY seq
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentUpdate::from).collect())
    }

    async fn find_by_document_id_after_seq(
        &self,
        document_id: DocumentId,
        after_seq: i64,
    ) -> Result<Vec<DocumentUpdate>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentUpdateRow>(
            r#"
            SELECT id, document_id, seq, update_data, nonce, key_version, update_hash,
                   prev_update_hash, signature, author_device_id, timestamp, created_at
            FROM document_updates
            WHERE document_id = $1 AND seq > $2
            ORDER BY seq
            "#,
        )
        .bind(document_id.as_uuid())
        .bind(after_seq)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentUpdate::from).collect())
    }

    async fn find_by_hash(&self, update_hash: &str) -> Result<Option<DocumentUpdate>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentUpdateRow>(
            r#"
            SELECT id, document_id, seq, update_data, nonce, key_version, update_hash,
                   prev_update_hash, signature, author_device_id, timestamp, created_at
            FROM document_updates
            WHERE update_hash = $1
            "#,
        )
        .bind(update_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentUpdate::from))
    }

    async fn get_latest_seq(&self, document_id: DocumentId) -> Result<Option<i64>, Self::Error> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT MAX(seq) FROM document_updates WHERE document_id = $1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, update: &DocumentUpdate) -> Result<i64, Self::Error> {
        let id = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO document_updates (
                document_id, seq, update_data, nonce, key_version, update_hash,
                prev_update_hash, signature, author_device_id, timestamp, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
        )
        .bind(update.document_id.as_uuid())
        .bind(update.seq)
        .bind(&update.update_data)
        .bind(&update.nonce)
        .bind(update.key_version)
        .bind(&update.update_hash)
        .bind(&update.prev_update_hash)
        .bind(&update.signature)
        .bind(update.author_device_id.as_uuid())
        .bind(update.timestamp)
        .bind(update.created_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_before_seq(&self, document_id: DocumentId, before_seq: i64) -> Result<u64, Self::Error> {
        let result = sqlx::query("DELETE FROM document_updates WHERE document_id = $1 AND seq < $2")
            .bind(document_id.as_uuid())
            .bind(before_seq)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
