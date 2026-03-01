//! PostgreSQL document update repository implementation (clock-based)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{DocumentId, DocumentSnapshotId, DocumentUpdate, DocumentUpdateRepository};
use thiserror::Error;
use uuid::Uuid;

pg_repo_struct!(PgDocumentUpdateRepository);

#[derive(Debug, Error)]
pub enum PgDocumentUpdateRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("clock mismatch: expected next clock value")]
    ClockMismatch,

    #[error("snapshot mismatch: ref_snapshot_id does not match active")]
    SnapshotMismatch,

    #[error("key version too old: below min_dek_version")]
    KeyVersionTooOld,
}

#[derive(sqlx::FromRow)]
struct DocumentUpdateRow {
    id: i64,
    document_id: Uuid,
    update_data: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i32,
    update_hash: String,
    signature: Vec<u8>,
    timestamp: i64,
    snapshot_id: Uuid,
    clock: i32,
    version: i64,
    device_signing_pub_key: String,
    public_data: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl From<DocumentUpdateRow> for (DocumentUpdate, serde_json::Value) {
    fn from(row: DocumentUpdateRow) -> Self {
        let public_data = row.public_data;
        let update = DocumentUpdate {
            id: row.id,
            document_id: DocumentId::from_uuid(row.document_id),
            update_data: row.update_data,
            nonce: row.nonce,
            key_version: row.key_version,
            update_hash: row.update_hash,
            signature: row.signature,
            timestamp: row.timestamp,
            snapshot_id: DocumentSnapshotId::from_uuid(row.snapshot_id),
            clock: row.clock,
            version: row.version,
            device_signing_pub_key: row.device_signing_pub_key,
            created_at: row.created_at,
        };
        (update, public_data)
    }
}

const UPDATE_COLUMNS: &str = "id, document_id, update_data, nonce, key_version, update_hash, signature, timestamp, snapshot_id, clock, version, device_signing_pub_key, public_data, created_at";

#[async_trait]
impl DocumentUpdateRepository for PgDocumentUpdateRepository {
    type Error = PgDocumentUpdateRepositoryError;

    async fn find_by_snapshot_id(
        &self,
        snapshot_id: DocumentSnapshotId,
        after_version: Option<i64>,
    ) -> Result<Vec<(DocumentUpdate, serde_json::Value)>, Self::Error> {
        let rows = if let Some(after_ver) = after_version {
            let sql = format!(
                "SELECT {UPDATE_COLUMNS} FROM document_updates WHERE snapshot_id = $1 AND version > $2 ORDER BY version"
            );
            sqlx::query_as::<_, DocumentUpdateRow>(&sql)
                .bind(snapshot_id.as_uuid())
                .bind(after_ver)
                .fetch_all(&self.pool)
                .await?
        } else {
            let sql = format!(
                "SELECT {UPDATE_COLUMNS} FROM document_updates WHERE snapshot_id = $1 ORDER BY version"
            );
            sqlx::query_as::<_, DocumentUpdateRow>(&sql)
                .bind(snapshot_id.as_uuid())
                .fetch_all(&self.pool)
                .await?
        };

        Ok(rows.into_iter().map(<(DocumentUpdate, serde_json::Value)>::from).collect())
    }

    async fn save_with_clock(
        &self,
        update: &DocumentUpdate,
        snapshot_id: DocumentSnapshotId,
        public_data: serde_json::Value,
    ) -> Result<(i64, i32, i64), Self::Error> {
        // Use SERIALIZABLE transaction to prevent concurrent clock races.
        // Atomic INSERT: auto-assign version, verify clock is next expected value
        // for the device within this snapshot.
        // Clock verification: expected_clock = COALESCE(MAX(clock) + 1, 0) for this (snapshot, device)
        // Also verifies that the referenced snapshot is still the active snapshot (prevents
        // writes to a stale snapshot after a new snapshot has been activated).
        let mut tx = self.pool.begin().await.map_err(PgDocumentUpdateRepositoryError::Database)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(PgDocumentUpdateRepositoryError::Database)?;

        let row = sqlx::query_as::<_, (i64, i32, i64)>(
            r#"
            INSERT INTO document_updates (
                document_id, update_data, nonce, key_version, update_hash,
                signature, timestamp, snapshot_id, clock,
                version, device_signing_pub_key, public_data, created_at
            )
            SELECT
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                COALESCE(
                    (SELECT MAX(version) FROM document_updates WHERE snapshot_id = $8), 0
                ) + 1,
                $10, $11, $12
            WHERE $9 = COALESCE(
                (SELECT MAX(clock) + 1
                 FROM document_updates
                 WHERE snapshot_id = $8 AND device_signing_pub_key = $10),
                0
            )
            AND EXISTS (
                SELECT 1 FROM documents
                WHERE id = $1 AND active_snapshot_id = $8
                AND min_dek_version <= $4
            )
            RETURNING id, clock, version
            "#,
        )
        .bind(update.document_id.as_uuid())       // $1
        .bind(&update.update_data)                 // $2
        .bind(&update.nonce)                       // $3
        .bind(update.key_version)                  // $4
        .bind(&update.update_hash)                 // $5
        .bind(&update.signature)                   // $6
        .bind(update.timestamp)                    // $7
        .bind(snapshot_id.as_uuid())               // $8
        .bind(update.clock)                        // $9
        .bind(&update.device_signing_pub_key)      // $10
        .bind(&public_data)                        // $11
        .bind(update.created_at)                   // $12
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                // Serialization failure (concurrent transaction conflict)
                if db_err.code().as_deref() == Some("40001") {
                    return PgDocumentUpdateRepositoryError::ClockMismatch;
                }
                if db_err.code().as_deref() == Some("23505") {
                    return PgDocumentUpdateRepositoryError::ClockMismatch;
                }
            }
            PgDocumentUpdateRepositoryError::Database(e)
        })?;

        match row {
            Some((id, clock, version)) => {
                // Update snapshot metadata to keep clocks and latest_version in sync
                // (design: websocket-scaling.md lines 237-241)
                sqlx::query(
                    r#"
                    UPDATE document_snapshots
                    SET clocks = jsonb_set(clocks, ARRAY[$1], to_jsonb($2::int)),
                        latest_version = $3
                    WHERE id = $4
                    "#,
                )
                .bind(&update.device_signing_pub_key)  // $1
                .bind(clock)                           // $2
                .bind(version)                         // $3
                .bind(snapshot_id.as_uuid())            // $4
                .execute(&mut *tx)
                .await
                .map_err(PgDocumentUpdateRepositoryError::Database)?;

                tx.commit().await.map_err(|e| {
                    if let sqlx::Error::Database(ref db_err) = e {
                        if db_err.code().as_deref() == Some("40001") {
                            return PgDocumentUpdateRepositoryError::ClockMismatch;
                        }
                    }
                    PgDocumentUpdateRepositoryError::Database(e)
                })?;
                Ok((id, clock, version))
            }
            None => {
                // Distinguish snapshot mismatch, key version too old, and clock mismatch.
                // Check active snapshot and min_dek_version within the same transaction.
                let diag = sqlx::query_as::<_, (bool, bool)>(
                    r#"SELECT
                        EXISTS(SELECT 1 FROM documents WHERE id = $1 AND active_snapshot_id = $2),
                        EXISTS(SELECT 1 FROM documents WHERE id = $1 AND min_dek_version <= $3)
                    "#
                )
                .bind(update.document_id.as_uuid())
                .bind(snapshot_id.as_uuid())
                .bind(update.key_version)
                .fetch_one(&mut *tx)
                .await
                .map(|r| (r.0, r.1))
                .unwrap_or((false, true));

                tx.rollback().await.map_err(PgDocumentUpdateRepositoryError::Database)?;

                let (active_matches, key_version_ok) = diag;
                if !active_matches {
                    Err(PgDocumentUpdateRepositoryError::SnapshotMismatch)
                } else if !key_version_ok {
                    Err(PgDocumentUpdateRepositoryError::KeyVersionTooOld)
                } else {
                    Err(PgDocumentUpdateRepositoryError::ClockMismatch)
                }
            }
        }
    }

    fn is_clock_mismatch(&self, err: &Self::Error) -> bool {
        matches!(err, PgDocumentUpdateRepositoryError::ClockMismatch)
    }

    fn is_snapshot_mismatch(&self, err: &Self::Error) -> bool {
        matches!(err, PgDocumentUpdateRepositoryError::SnapshotMismatch)
    }

    fn is_key_version_too_old(&self, err: &Self::Error) -> bool {
        matches!(err, PgDocumentUpdateRepositoryError::KeyVersionTooOld)
    }

    async fn find_by_snapshot_id_after_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
        known_clocks: &std::collections::HashMap<String, i64>,
    ) -> Result<Vec<(DocumentUpdate, serde_json::Value)>, Self::Error> {
        let clocks_json = serde_json::to_value(known_clocks)
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let sql = format!(
            r#"SELECT {UPDATE_COLUMNS} FROM document_updates
            WHERE snapshot_id = $1
            AND (
                NOT ($2::jsonb ? device_signing_pub_key)
                OR clock > ($2::jsonb ->> device_signing_pub_key)::integer
            )
            ORDER BY version"#
        );
        let rows = sqlx::query_as::<_, DocumentUpdateRow>(&sql)
            .bind(snapshot_id.as_uuid())
            .bind(&clocks_json)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(<(DocumentUpdate, serde_json::Value)>::from).collect())
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
