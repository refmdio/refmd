use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::document_keys_repository::{
    DocumentEncryptedKeyRow, DocumentKeysRepository,
};

pub struct SqlxDocumentKeysRepository {
    pool: PgPool,
}

impl SqlxDocumentKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocumentKeysRepository for SqlxDocumentKeysRepository {
    async fn get_encrypted_dek(
        &self,
        document_id: Uuid,
    ) -> PortResult<Option<DocumentEncryptedKeyRow>> {
        let out: anyhow::Result<Option<DocumentEncryptedKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT document_id, encrypted_dek, nonce, key_version, created_at, updated_at
                   FROM document_encrypted_keys
                   WHERE document_id = $1"#,
            )
            .bind(document_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| DocumentEncryptedKeyRow {
                document_id: row.get("document_id"),
                encrypted_dek: row.get("encrypted_dek"),
                nonce: row.get("nonce"),
                key_version: row.get("key_version"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_encrypted_dek(
        &self,
        document_id: Uuid,
        encrypted_dek: &[u8],
        nonce: &[u8],
        key_version: i32,
    ) -> PortResult<DocumentEncryptedKeyRow> {
        let out: anyhow::Result<DocumentEncryptedKeyRow> = async {
            let row = sqlx::query(
                r#"INSERT INTO document_encrypted_keys (document_id, encrypted_dek, nonce, key_version, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, now(), now())
                   ON CONFLICT (document_id)
                   DO UPDATE SET
                     encrypted_dek = EXCLUDED.encrypted_dek,
                     nonce = EXCLUDED.nonce,
                     key_version = EXCLUDED.key_version,
                     updated_at = now()
                   RETURNING document_id, encrypted_dek, nonce, key_version, created_at, updated_at"#,
            )
            .bind(document_id)
            .bind(encrypted_dek)
            .bind(nonce)
            .bind(key_version)
            .fetch_one(&self.pool)
            .await?;

            Ok(DocumentEncryptedKeyRow {
                document_id: row.get("document_id"),
                encrypted_dek: row.get("encrypted_dek"),
                nonce: row.get("nonce"),
                key_version: row.get("key_version"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_encrypted_dek(&self, document_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let result = sqlx::query(r#"DELETE FROM document_encrypted_keys WHERE document_id = $1"#)
                .bind(document_id)
                .execute(&self.pool)
                .await?;

            Ok(result.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }
}
