use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::realtime::realtime_persistence_port::{
    ContentEncryptionMeta, DocPersistencePort, DocumentMissingError, EncryptedUpdateData,
    EncryptedUpdateEntry, SnapshotEntry,
};

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
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                "INSERT INTO document_updates (document_id, seq, update) VALUES ($1, $2, $3)",
            )
            .bind(doc_id)
            .bind(seq)
            .bind(update)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn append_encrypted_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &EncryptedUpdateData,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO document_updates (document_id, seq, update, nonce, signature, public_key)
                   VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(doc_id)
            .bind(seq)
            .bind(&update.data)
            .bind(update.nonce.as_deref())
            .bind(update.signature.as_deref())
            .bind(update.public_key.as_deref())
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn latest_update_seq(&self, doc_id: &Uuid) -> PortResult<Option<i64>> {
        let out: anyhow::Result<Option<i64>> = async {
            let row = sqlx::query(
                "SELECT MAX(seq) AS max_seq FROM document_updates WHERE document_id = $1",
            )
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.and_then(|row| row.try_get("max_seq").ok()))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        version: i64,
        snapshot: &[u8],
        encryption_meta: Option<&ContentEncryptionMeta>,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let (nonce, signature, seq_at_snapshot) = encryption_meta
                .map(|m| (m.nonce.as_deref(), m.signature.as_deref(), m.seq_at_snapshot))
                .unwrap_or((None, None, None));
            let result = sqlx::query(
                "INSERT INTO document_snapshots (document_id, version, snapshot, nonce, signature, seq_at_snapshot) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (document_id, version) DO UPDATE SET snapshot = EXCLUDED.snapshot, nonce = EXCLUDED.nonce, signature = EXCLUDED.signature, seq_at_snapshot = EXCLUDED.seq_at_snapshot",
            )
            .bind(doc_id)
            .bind(version as i32)
            .bind(snapshot)
            .bind(nonce)
            .bind(signature)
            .bind(seq_at_snapshot)
            .execute(&self.pool)
            .await;

            match result {
                Ok(_) => Ok(()),
                Err(sqlx::Error::Database(db_err))
                    if matches!(
                        db_err.constraint(),
                        Some("document_snapshots_document_id_fkey")
                    ) =>
                {
                    Err(DocumentMissingError {
                        document_id: *doc_id,
                    }
                    .into())
                }
                Err(err) => Err(err.into()),
            }
        }
        .await;
        out.map_err(Into::into)
    }

    async fn latest_snapshot_entry(&self, doc_id: &Uuid) -> PortResult<Option<SnapshotEntry>> {
        let out: anyhow::Result<Option<SnapshotEntry>> = async {
            let row = sqlx::query(
                "SELECT version, snapshot, nonce, signature, seq_at_snapshot FROM document_snapshots WHERE document_id = $1
             ORDER BY version DESC LIMIT 1",
            )
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|row| SnapshotEntry {
                version: row.get::<i32, _>("version") as i64,
                bytes: row.get("snapshot"),
                nonce: row.try_get("nonce").ok(),
                signature: row.try_get("signature").ok(),
                seq_at_snapshot: row.try_get("seq_at_snapshot").ok().flatten(),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn latest_snapshot_version(&self, doc_id: &Uuid) -> PortResult<Option<i64>> {
        let out: anyhow::Result<Option<i64>> = async {
            Ok(self
                .latest_snapshot_entry(doc_id)
                .await?
                .map(|entry| entry.version))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn prune_snapshots(&self, doc_id: &Uuid, keep_latest: i64) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
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
        .await;
        out.map_err(Into::into)
    }

    async fn prune_updates_before(&self, doc_id: &Uuid, seq_inclusive: i64) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM document_updates WHERE document_id = $1 AND seq <= $2")
                .bind(doc_id)
                .bind(seq_inclusive)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn clear_updates(&self, doc_id: &Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
                .bind(doc_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_updates_since(
        &self,
        doc_id: &Uuid,
        since_seq: i64,
    ) -> PortResult<Vec<EncryptedUpdateEntry>> {
        let out: anyhow::Result<Vec<EncryptedUpdateEntry>> = async {
            let rows = sqlx::query(
                r#"SELECT seq, update, nonce, signature, public_key
                   FROM document_updates
                   WHERE document_id = $1 AND seq > $2
                   ORDER BY seq ASC"#,
            )
            .bind(doc_id)
            .bind(since_seq)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| EncryptedUpdateEntry {
                    seq: row.get("seq"),
                    data: row.get("update"),
                    nonce: row.try_get("nonce").ok().flatten(),
                    signature: row.try_get("signature").ok().flatten(),
                    public_key: row.try_get("public_key").ok().flatten(),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }
}
