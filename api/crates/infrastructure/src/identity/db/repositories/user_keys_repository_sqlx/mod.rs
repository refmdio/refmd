use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::identity::ports::user_keys_repository::{
    UserEncryptedMasterKeyRow, UserEncryptedPrivateKeyRow, UserKeysRepository, UserPublicKeyRow,
};
use domain::identity::keys::{KdfParams, KdfType, KeyType};

pub struct SqlxUserKeysRepository {
    pool: PgPool,
}

impl SqlxUserKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserKeysRepository for SqlxUserKeysRepository {
    async fn get_public_key(&self, user_id: Uuid) -> PortResult<Option<UserPublicKeyRow>> {
        let out: anyhow::Result<Option<UserPublicKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT user_id, public_key, key_type, created_at, updated_at
                   FROM user_public_keys
                   WHERE user_id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| {
                let key_type_str: String = row.get("key_type");
                UserPublicKeyRow {
                    user_id: row.get("user_id"),
                    public_key: row.get("public_key"),
                    key_type: KeyType::parse(&key_type_str).unwrap_or(KeyType::EcdhP256),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_public_key(
        &self,
        user_id: Uuid,
        public_key: &[u8],
        key_type: KeyType,
    ) -> PortResult<UserPublicKeyRow> {
        let out: anyhow::Result<UserPublicKeyRow> = async {
            let row = sqlx::query(
                r#"INSERT INTO user_public_keys (user_id, public_key, key_type, created_at, updated_at)
                   VALUES ($1, $2, $3, now(), now())
                   ON CONFLICT (user_id)
                   DO UPDATE SET
                     public_key = EXCLUDED.public_key,
                     key_type = EXCLUDED.key_type,
                     updated_at = now()
                   RETURNING user_id, public_key, key_type, created_at, updated_at"#,
            )
            .bind(user_id)
            .bind(public_key)
            .bind(key_type.as_str())
            .fetch_one(&self.pool)
            .await?;

            let key_type_str: String = row.get("key_type");
            Ok(UserPublicKeyRow {
                user_id: row.get("user_id"),
                public_key: row.get("public_key"),
                key_type: KeyType::parse(&key_type_str).unwrap_or(KeyType::EcdhP256),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_encrypted_master_key(
        &self,
        user_id: Uuid,
    ) -> PortResult<Option<UserEncryptedMasterKeyRow>> {
        let out: anyhow::Result<Option<UserEncryptedMasterKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT user_id, encrypted_key, salt, kdf_type, kdf_params, created_at, updated_at
                   FROM user_encrypted_master_keys
                   WHERE user_id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| {
                let kdf_type_str: String = row.get("kdf_type");
                let kdf_params_json: serde_json::Value = row.get("kdf_params");
                UserEncryptedMasterKeyRow {
                    user_id: row.get("user_id"),
                    encrypted_key: row.get("encrypted_key"),
                    salt: row.get("salt"),
                    kdf_type: KdfType::parse(&kdf_type_str).unwrap_or(KdfType::Argon2id),
                    kdf_params: serde_json::from_value(kdf_params_json).unwrap_or_default(),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_encrypted_master_key(
        &self,
        user_id: Uuid,
        encrypted_key: &[u8],
        salt: &[u8],
        kdf_type: KdfType,
        kdf_params: &KdfParams,
    ) -> PortResult<UserEncryptedMasterKeyRow> {
        let out: anyhow::Result<UserEncryptedMasterKeyRow> = async {
            let kdf_params_json = serde_json::to_value(kdf_params)?;
            let row = sqlx::query(
                r#"INSERT INTO user_encrypted_master_keys (user_id, encrypted_key, salt, kdf_type, kdf_params, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, now(), now())
                   ON CONFLICT (user_id)
                   DO UPDATE SET
                     encrypted_key = EXCLUDED.encrypted_key,
                     salt = EXCLUDED.salt,
                     kdf_type = EXCLUDED.kdf_type,
                     kdf_params = EXCLUDED.kdf_params,
                     updated_at = now()
                   RETURNING user_id, encrypted_key, salt, kdf_type, kdf_params, created_at, updated_at"#,
            )
            .bind(user_id)
            .bind(encrypted_key)
            .bind(salt)
            .bind(kdf_type.as_str())
            .bind(&kdf_params_json)
            .fetch_one(&self.pool)
            .await?;

            let kdf_type_str: String = row.get("kdf_type");
            let kdf_params_json: serde_json::Value = row.get("kdf_params");
            Ok(UserEncryptedMasterKeyRow {
                user_id: row.get("user_id"),
                encrypted_key: row.get("encrypted_key"),
                salt: row.get("salt"),
                kdf_type: KdfType::parse(&kdf_type_str).unwrap_or(KdfType::Argon2id),
                kdf_params: serde_json::from_value(kdf_params_json).unwrap_or_default(),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_encrypted_private_key(
        &self,
        user_id: Uuid,
    ) -> PortResult<Option<UserEncryptedPrivateKeyRow>> {
        let out: anyhow::Result<Option<UserEncryptedPrivateKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT user_id, encrypted_private_key, nonce, created_at, updated_at
                   FROM user_encrypted_private_keys
                   WHERE user_id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| UserEncryptedPrivateKeyRow {
                user_id: row.get("user_id"),
                encrypted_private_key: row.get("encrypted_private_key"),
                nonce: row.get("nonce"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_encrypted_private_key(
        &self,
        user_id: Uuid,
        encrypted_private_key: &[u8],
        nonce: &[u8],
    ) -> PortResult<UserEncryptedPrivateKeyRow> {
        let out: anyhow::Result<UserEncryptedPrivateKeyRow> = async {
            let row = sqlx::query(
                r#"INSERT INTO user_encrypted_private_keys (user_id, encrypted_private_key, nonce, created_at, updated_at)
                   VALUES ($1, $2, $3, now(), now())
                   ON CONFLICT (user_id)
                   DO UPDATE SET
                     encrypted_private_key = EXCLUDED.encrypted_private_key,
                     nonce = EXCLUDED.nonce,
                     updated_at = now()
                   RETURNING user_id, encrypted_private_key, nonce, created_at, updated_at"#,
            )
            .bind(user_id)
            .bind(encrypted_private_key)
            .bind(nonce)
            .fetch_one(&self.pool)
            .await?;

            Ok(UserEncryptedPrivateKeyRow {
                user_id: row.get("user_id"),
                encrypted_private_key: row.get("encrypted_private_key"),
                nonce: row.get("nonce"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn mark_e2ee_setup_completed(&self, user_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"UPDATE users SET e2ee_setup_completed_at = now() WHERE id = $1"#,
            )
            .bind(user_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn is_e2ee_setup_completed(&self, user_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let row = sqlx::query(
                r#"SELECT e2ee_setup_completed_at FROM users WHERE id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row
                .and_then(|r| r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("e2ee_setup_completed_at").ok())
                .flatten()
                .is_some())
        }
        .await;
        out.map_err(Into::into)
    }
}
