use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::share_keys_repository::{ShareEncryptedKeyRow, ShareKeysRepository};
use domain::identity::keys::KdfParams;

pub struct SqlxShareKeysRepository {
    pool: PgPool,
}

impl SqlxShareKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ShareKeysRepository for SqlxShareKeysRepository {
    async fn get_encrypted_dek(&self, share_id: Uuid) -> PortResult<Option<ShareEncryptedKeyRow>> {
        let out: anyhow::Result<Option<ShareEncryptedKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT share_id, encrypted_dek, salt, kdf_params, created_at
                   FROM share_encrypted_keys
                   WHERE share_id = $1"#,
            )
            .bind(share_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| {
                let kdf_params_json: Option<serde_json::Value> = row.get("kdf_params");
                ShareEncryptedKeyRow {
                    share_id: row.get("share_id"),
                    encrypted_dek: row.get("encrypted_dek"),
                    salt: row.get("salt"),
                    kdf_params: kdf_params_json.and_then(|v| serde_json::from_value(v).ok()),
                    created_at: row.get("created_at"),
                }
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_salt(&self, share_id: Uuid) -> PortResult<Option<Vec<u8>>> {
        let out: anyhow::Result<Option<Vec<u8>>> = async {
            let row = sqlx::query(r#"SELECT salt FROM share_encrypted_keys WHERE share_id = $1"#)
                .bind(share_id)
                .fetch_optional(&self.pool)
                .await?;

            Ok(row.and_then(|r| r.get("salt")))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn store_encrypted_dek(
        &self,
        share_id: Uuid,
        encrypted_dek: &[u8],
    ) -> PortResult<ShareEncryptedKeyRow> {
        let out: anyhow::Result<ShareEncryptedKeyRow> = async {
            let row = sqlx::query(
                r#"INSERT INTO share_encrypted_keys (share_id, encrypted_dek, created_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (share_id)
                   DO UPDATE SET
                     encrypted_dek = EXCLUDED.encrypted_dek,
                     salt = NULL,
                     kdf_params = NULL
                   RETURNING share_id, encrypted_dek, salt, kdf_params, created_at"#,
            )
            .bind(share_id)
            .bind(encrypted_dek)
            .fetch_one(&self.pool)
            .await?;

            let kdf_params_json: Option<serde_json::Value> = row.get("kdf_params");
            Ok(ShareEncryptedKeyRow {
                share_id: row.get("share_id"),
                encrypted_dek: row.get("encrypted_dek"),
                salt: row.get("salt"),
                kdf_params: kdf_params_json.and_then(|v| serde_json::from_value(v).ok()),
                created_at: row.get("created_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn store_password_protected_dek(
        &self,
        share_id: Uuid,
        encrypted_dek: &[u8],
        salt: &[u8],
        kdf_params: &KdfParams,
    ) -> PortResult<ShareEncryptedKeyRow> {
        let out: anyhow::Result<ShareEncryptedKeyRow> = async {
            let kdf_params_json = serde_json::to_value(kdf_params)?;
            let row = sqlx::query(
                r#"INSERT INTO share_encrypted_keys (share_id, encrypted_dek, salt, kdf_params, created_at)
                   VALUES ($1, $2, $3, $4, now())
                   ON CONFLICT (share_id)
                   DO UPDATE SET
                     encrypted_dek = EXCLUDED.encrypted_dek,
                     salt = EXCLUDED.salt,
                     kdf_params = EXCLUDED.kdf_params
                   RETURNING share_id, encrypted_dek, salt, kdf_params, created_at"#,
            )
            .bind(share_id)
            .bind(encrypted_dek)
            .bind(salt)
            .bind(&kdf_params_json)
            .fetch_one(&self.pool)
            .await?;

            let kdf_params_json: Option<serde_json::Value> = row.get("kdf_params");
            Ok(ShareEncryptedKeyRow {
                share_id: row.get("share_id"),
                encrypted_dek: row.get("encrypted_dek"),
                salt: row.get("salt"),
                kdf_params: kdf_params_json.and_then(|v| serde_json::from_value(v).ok()),
                created_at: row.get("created_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_encrypted_dek(&self, share_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let result = sqlx::query(r#"DELETE FROM share_encrypted_keys WHERE share_id = $1"#)
                .bind(share_id)
                .execute(&self.pool)
                .await?;

            Ok(result.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }
}
