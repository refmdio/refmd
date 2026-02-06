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

    #[error("duplicate update hash")]
    DuplicateHash,

    #[error("chain mismatch: prev_update_hash does not match latest")]
    ChainMismatch,
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

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentUpdate>, Self::Error> {
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

    async fn get_latest_update_hash(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<String>, Self::Error> {
        let result = sqlx::query_scalar::<_, String>(
            r#"
            SELECT update_hash FROM document_updates
            WHERE document_id = $1 ORDER BY seq DESC LIMIT 1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, update: &DocumentUpdate) -> Result<(i64, i64), Self::Error> {
        // Atomic INSERT: auto-assign seq and verify prev_update_hash chain in a single query.
        // If prev_update_hash doesn't match the latest update's hash, no row is inserted.
        // If (document_id, seq) UNIQUE constraint is violated, it's a concurrent race.
        let result = sqlx::query_as::<_, (i64, i64)>(
            r#"
            INSERT INTO document_updates (
                document_id, seq, update_data, nonce, key_version, update_hash,
                prev_update_hash, signature, author_device_id, timestamp, created_at
            )
            SELECT
                $1,
                COALESCE((SELECT MAX(seq) FROM document_updates WHERE document_id = $1), 0) + 1,
                $2, $3, $4, $5, $6, $7, $8, $9, $10
            WHERE (
                ($6 IS NULL AND NOT EXISTS (SELECT 1 FROM document_updates WHERE document_id = $1))
                OR
                ($6 IS NOT NULL AND $6 = (SELECT update_hash FROM document_updates WHERE document_id = $1 ORDER BY seq DESC LIMIT 1))
            )
            RETURNING id, seq
            "#,
        )
        .bind(update.document_id.as_uuid()) // $1: document_id
        .bind(&update.update_data)           // $2: update_data
        .bind(&update.nonce)                 // $3: nonce
        .bind(update.key_version)            // $4: key_version
        .bind(&update.update_hash)           // $5: update_hash
        .bind(&update.prev_update_hash)      // $6: prev_update_hash
        .bind(&update.signature)             // $7: signature
        .bind(update.author_device_id.as_uuid()) // $8: author_device_id
        .bind(update.timestamp)              // $9: timestamp
        .bind(update.created_at)             // $10: created_at
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            // Check for UNIQUE violation (PostgreSQL error code 23505)
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.code().as_deref() == Some("23505") {
                    // Check which constraint was violated
                    let message = db_err.message();
                    if message.contains("update_hash") {
                        return PgDocumentUpdateRepositoryError::DuplicateHash;
                    }
                    // seq UNIQUE violation = concurrent race, treat as chain mismatch
                    return PgDocumentUpdateRepositoryError::ChainMismatch;
                }
            }
            PgDocumentUpdateRepositoryError::Database(e)
        })?;

        match result {
            Some((id, seq)) => Ok((id, seq)),
            // No row inserted = chain mismatch (WHERE clause didn't match)
            None => Err(PgDocumentUpdateRepositoryError::ChainMismatch),
        }
    }

    fn is_duplicate_hash(err: &Self::Error) -> bool {
        matches!(err, PgDocumentUpdateRepositoryError::DuplicateHash)
    }

    fn is_chain_mismatch(err: &Self::Error) -> bool {
        matches!(err, PgDocumentUpdateRepositoryError::ChainMismatch)
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_before_seq(
        &self,
        document_id: DocumentId,
        before_seq: i64,
    ) -> Result<u64, Self::Error> {
        let result =
            sqlx::query("DELETE FROM document_updates WHERE document_id = $1 AND seq < $2")
                .bind(document_id.as_uuid())
                .bind(before_seq)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected())
    }
}
