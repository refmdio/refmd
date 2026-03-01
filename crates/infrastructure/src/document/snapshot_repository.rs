//! PostgreSQL document snapshot repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{
    DocumentId, DocumentSnapshot, DocumentSnapshotId, DocumentSnapshotRepository, SnapshotProof,
};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

pg_repo_struct!(PgSnapshotRepository);

#[derive(Debug, Error)]
pub enum PgSnapshotRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct SnapshotRow {
    id: Uuid,
    document_id: Uuid,
    latest_version: i64,
    data: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i32,
    signature: Vec<u8>,
    ciphertext_hash: String,
    clocks: serde_json::Value,
    parent_snapshot_update_clocks: serde_json::Value,
    parent_snapshot_proof: String,
    created_by_device: String,
    public_data: serde_json::Value,
    created_at: DateTime<Utc>,
}

fn jsonb_to_hashmap(v: &serde_json::Value) -> HashMap<String, i64> {
    match v {
        serde_json::Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n)))
            .collect(),
        _ => HashMap::new(),
    }
}

fn hashmap_to_jsonb(m: &HashMap<String, i64>) -> serde_json::Value {
    serde_json::Value::Object(
        m.iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::Number((*v).into())))
            .collect(),
    )
}

impl From<SnapshotRow> for (DocumentSnapshot, serde_json::Value) {
    fn from(row: SnapshotRow) -> Self {
        let public_data = row.public_data;
        let snapshot = DocumentSnapshot {
            id: DocumentSnapshotId::from_uuid(row.id),
            document_id: DocumentId::from_uuid(row.document_id),
            latest_version: row.latest_version,
            data: row.data,
            nonce: row.nonce,
            key_version: row.key_version,
            signature: row.signature,
            ciphertext_hash: row.ciphertext_hash,
            clocks: jsonb_to_hashmap(&row.clocks),
            parent_snapshot_update_clocks: jsonb_to_hashmap(&row.parent_snapshot_update_clocks),
            parent_snapshot_proof: row.parent_snapshot_proof,
            created_by_device: row.created_by_device,
            created_at: row.created_at,
        };
        (snapshot, public_data)
    }
}

#[async_trait]
impl DocumentSnapshotRepository for PgSnapshotRepository {
    type Error = PgSnapshotRepositoryError;

    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<(DocumentSnapshot, serde_json::Value)>, Self::Error> {
        let row = sqlx::query_as::<_, SnapshotRow>(
            r#"
            SELECT cs.id, cs.document_id, cs.latest_version, cs.data, cs.nonce, cs.key_version,
                   cs.signature, cs.ciphertext_hash, cs.clocks, cs.parent_snapshot_update_clocks,
                   cs.parent_snapshot_proof, cs.created_by_device, cs.public_data, cs.created_at
            FROM document_snapshots cs
            JOIN documents d ON d.active_snapshot_id = cs.id
            WHERE d.id = $1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(<(DocumentSnapshot, serde_json::Value)>::from))
    }

    async fn find_by_id(
        &self,
        id: DocumentSnapshotId,
    ) -> Result<Option<(DocumentSnapshot, serde_json::Value)>, Self::Error> {
        let row = sqlx::query_as::<_, SnapshotRow>(
            r#"
            SELECT id, document_id, latest_version, data, nonce, key_version,
                   signature, ciphertext_hash, clocks, parent_snapshot_update_clocks,
                   parent_snapshot_proof, created_by_device, public_data, created_at
            FROM document_snapshots
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(<(DocumentSnapshot, serde_json::Value)>::from))
    }

    async fn save(
        &self,
        snapshot: &DocumentSnapshot,
        expected_parent_id: Option<DocumentSnapshotId>,
        expected_parent_clocks: &HashMap<String, i64>,
        public_data: serde_json::Value,
    ) -> Result<domain::document::SnapshotSaveOutcome, Self::Error> {
        use domain::document::SnapshotSaveOutcome;

        let clocks_json = hashmap_to_jsonb(&snapshot.clocks);
        let parent_clocks_json = hashmap_to_jsonb(&snapshot.parent_snapshot_update_clocks);

        let mut tx = self.pool.begin().await?;

        // Set Serializable isolation to prevent concurrent updates from slipping
        // between clock validation and snapshot save
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;

        // Clock validation INSIDE the transaction (skip for genesis — no parent updates exist)
        if let Some(parent_id) = expected_parent_id {
            let current_clocks_rows = sqlx::query_as::<_, (String, i64)>(
                r#"
                SELECT device_signing_pub_key, MAX(clock)::bigint
                FROM document_updates
                WHERE snapshot_id = $1
                GROUP BY device_signing_pub_key
                "#,
            )
            .bind(parent_id.as_uuid())
            .fetch_all(&mut *tx)
            .await?;

            let current_clocks: HashMap<String, i64> = current_clocks_rows.into_iter().collect();
            if current_clocks != *expected_parent_clocks {
                tx.rollback().await?;
                return Ok(SnapshotSaveOutcome::ClockMismatch);
            }
        }

        let insert_result = sqlx::query(
            r#"
            INSERT INTO document_snapshots (
                id, document_id, parent_snapshot_id, latest_version, data, nonce, key_version,
                signature, ciphertext_hash, clocks, parent_snapshot_update_clocks,
                parent_snapshot_proof, created_by_device, public_data, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(snapshot.id.as_uuid())
        .bind(snapshot.document_id.as_uuid())
        .bind(expected_parent_id.map(|id| id.as_uuid()))
        .bind(snapshot.latest_version)
        .bind(&snapshot.data)
        .bind(&snapshot.nonce)
        .bind(snapshot.key_version)
        .bind(&snapshot.signature)
        .bind(&snapshot.ciphertext_hash)
        .bind(&clocks_json)
        .bind(&parent_clocks_json)
        .bind(&snapshot.parent_snapshot_proof)
        .bind(&snapshot.created_by_device)
        .bind(&public_data)
        .bind(snapshot.created_at)
        .execute(&mut *tx)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(sqlx::Error::Database(ref db_err)) if db_err.is_unique_violation() => {
                tx.rollback().await?;
                return Ok(SnapshotSaveOutcome::DuplicateId);
            }
            Err(e) => return Err(e.into()),
        }

        // CAS: only update active_snapshot_id if current active matches expected parent
        // AND key_version meets min_dek_version (prevents TOCTOU race with DEK rotation)
        let result = match expected_parent_id {
            Some(parent_id) => {
                sqlx::query(
                    r#"
                    UPDATE documents SET active_snapshot_id = $1
                    WHERE id = $2 AND active_snapshot_id = $3
                    AND min_dek_version <= $4
                    "#,
                )
                .bind(snapshot.id.as_uuid())
                .bind(snapshot.document_id.as_uuid())
                .bind(parent_id.as_uuid())
                .bind(snapshot.key_version)
                .execute(&mut *tx)
                .await?
            }
            None => {
                // Genesis: CAS checks active_snapshot_id IS NULL
                sqlx::query(
                    r#"
                    UPDATE documents SET active_snapshot_id = $1
                    WHERE id = $2 AND active_snapshot_id IS NULL
                    AND min_dek_version <= $3
                    "#,
                )
                .bind(snapshot.id.as_uuid())
                .bind(snapshot.document_id.as_uuid())
                .bind(snapshot.key_version)
                .execute(&mut *tx)
                .await?
            }
        };

        if result.rows_affected() == 0 {
            // CAS failed: disambiguate parent mismatch vs key version too old
            let key_ok = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM documents WHERE id = $1 AND min_dek_version <= $2)"
            )
            .bind(snapshot.document_id.as_uuid())
            .bind(snapshot.key_version)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(true);

            tx.rollback().await?;
            if !key_ok {
                return Ok(SnapshotSaveOutcome::KeyVersionTooOld);
            }
            return Ok(SnapshotSaveOutcome::ParentMismatch);
        }

        tx.commit().await?;
        Ok(SnapshotSaveOutcome::Saved)
    }

    async fn find_proof_chain(
        &self,
        document_id: DocumentId,
        from_snapshot_id: DocumentSnapshotId,
        up_to_snapshot_id: DocumentSnapshotId,
    ) -> Result<Vec<SnapshotProof>, Self::Error> {
        // Walk the parent_snapshot_id chain from up_to_snapshot_id back to
        // from_snapshot_id (exclusive). Uses a recursive CTE for correctness —
        // no dependency on timestamp ordering or UUID comparison.
        // Returns snapshots in child→parent order; reversed at the end to get
        // parent→child (chronological) order for client verification.
        //
        // The recursion depth is bounded by the number of snapshots between
        // from and up_to (typically < 100). PostgreSQL default recursion limit
        // is sufficient.
        //
        // document_id filter on both anchor and recursive queries enforces
        // document-boundary isolation (defense-in-depth).
        let rows = sqlx::query_as::<_, (Uuid, String, String, Option<Uuid>)>(
            r#"
            WITH RECURSIVE chain AS (
                -- Start from up_to_snapshot (inclusive, document-scoped)
                SELECT id, ciphertext_hash, parent_snapshot_proof, parent_snapshot_id, 0 AS depth
                FROM document_snapshots
                WHERE id = $1 AND document_id = $3

                UNION ALL

                -- Walk parent chain until we reach from_snapshot (exclusive)
                SELECT s.id, s.ciphertext_hash, s.parent_snapshot_proof, s.parent_snapshot_id, c.depth + 1
                FROM document_snapshots s
                INNER JOIN chain c ON s.id = c.parent_snapshot_id
                WHERE c.parent_snapshot_id IS NOT NULL
                  AND c.parent_snapshot_id != $2
                  AND s.document_id = $3
            )
            SELECT id, ciphertext_hash, parent_snapshot_proof, parent_snapshot_id
            FROM chain
            ORDER BY depth ASC
            "#,
        )
        .bind(up_to_snapshot_id.as_uuid())
        .bind(from_snapshot_id.as_uuid())
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        // Verify that from_snapshot_id is actually an ancestor of up_to_snapshot_id.
        // The CTE walks until it reaches from_snapshot_id or the chain root.
        // If from_snapshot_id is NOT an ancestor, the oldest entry's parent_snapshot_id
        // will NOT be from_snapshot_id — return empty chain (client handles fail-closed).
        let ancestor_found = rows.last().is_some_and(|(_, _, _, parent_id)| {
            parent_id.as_ref() == Some(&from_snapshot_id.as_uuid())
        });
        if !ancestor_found {
            return Ok(vec![]);
        }

        // Reverse: CTE returns child→parent order, client expects parent→child
        let mut proofs: Vec<SnapshotProof> = rows
            .into_iter()
            .map(|(id, ciphertext_hash, parent_snapshot_proof, _)| SnapshotProof {
                snapshot_id: DocumentSnapshotId::from_uuid(id),
                ciphertext_hash,
                parent_snapshot_proof,
            })
            .collect();
        proofs.reverse();

        Ok(proofs)
    }

    async fn get_snapshot_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
    ) -> Result<HashMap<String, i64>, Self::Error> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT device_signing_pub_key, MAX(clock)::bigint
            FROM document_updates
            WHERE snapshot_id = $1
            GROUP BY device_signing_pub_key
            "#,
        )
        .bind(snapshot_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

}
