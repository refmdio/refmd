//! PostgreSQL user key repository implementations

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{
    AuthType, KdfParams, KdfType, UserEncryptedIdentityKey, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKey, UserEncryptedMasterKeyRepository, UserIdentityPublicKey,
    UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use thiserror::Error;
use uuid::Uuid;

// ============ UserIdentityPublicKey Repository ============

pg_repo_struct!(PgUserIdentityPublicKeyRepository);
pg_repo_error!(PgUserIdentityPublicKeyRepositoryError);

#[derive(sqlx::FromRow)]
struct UserIdentityPublicKeyRow {
    user_id: Uuid,
    ecdh_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserIdentityPublicKeyRow> for UserIdentityPublicKey {
    fn from(row: UserIdentityPublicKeyRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            ecdh_public_key: row.ecdh_public_key,
            signing_public_key: row.signing_public_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserIdentityPublicKeyRepository for PgUserIdentityPublicKeyRepository {
    type Error = PgUserIdentityPublicKeyRepositoryError;

    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserIdentityPublicKey>, Self::Error> {
        let row = sqlx::query_as!(
            UserIdentityPublicKeyRow,
            r#"
            SELECT user_id, ecdh_public_key, signing_public_key, created_at, updated_at
            FROM user_identity_public_keys
            WHERE user_id = $1
            "#,
            user_id.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(UserIdentityPublicKey::from))
    }

    async fn save(&self, key: &UserIdentityPublicKey) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO user_identity_public_keys (user_id, ecdh_public_key, signing_public_key, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE SET
                ecdh_public_key = EXCLUDED.ecdh_public_key,
                signing_public_key = EXCLUDED.signing_public_key,
                updated_at = EXCLUDED.updated_at
            "#,
            key.user_id.as_uuid(),
            &key.ecdh_public_key,
            &key.signing_public_key,
            key.created_at,
            key.updated_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM user_identity_public_keys WHERE user_id = $1",
            user_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ UserEncryptedMasterKey Repository ============

pg_repo_struct!(PgUserEncryptedMasterKeyRepository);

#[derive(Debug, Error)]
pub enum PgUserEncryptedMasterKeyRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid auth type: {0}")]
    InvalidAuthType(String),

    #[error("corrupted data: invalid KDF type: {0}")]
    InvalidKdfType(String),
}

#[derive(sqlx::FromRow)]
struct UserEncryptedMasterKeyRow {
    user_id: Uuid,
    auth_type: String,
    encrypted_umk: Option<Vec<u8>>,
    umk_nonce: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    kdf_type: Option<String>,
    kdf_params: Option<sqlx::types::Json<KdfParams>>,
    auth_key_hash: Option<String>,
    recovery_encrypted_umk: Vec<u8>,
    recovery_nonce: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserEncryptedMasterKeyRow {
    fn try_into_key(
        self,
    ) -> Result<UserEncryptedMasterKey, PgUserEncryptedMasterKeyRepositoryError> {
        let auth_type: AuthType = self.auth_type.parse().map_err(|_| {
            PgUserEncryptedMasterKeyRepositoryError::InvalidAuthType(self.auth_type.clone())
        })?;

        let kdf_type = self
            .kdf_type
            .map(|s| {
                s.parse::<KdfType>()
                    .map_err(|_| PgUserEncryptedMasterKeyRepositoryError::InvalidKdfType(s))
            })
            .transpose()?;

        Ok(UserEncryptedMasterKey {
            user_id: UserId::from_uuid(self.user_id),
            auth_type,
            encrypted_umk: self.encrypted_umk,
            umk_nonce: self.umk_nonce,
            salt: self.salt,
            kdf_type,
            kdf_params: self.kdf_params.map(|p| p.0),
            auth_key_hash: self.auth_key_hash,
            recovery_encrypted_umk: self.recovery_encrypted_umk,
            recovery_nonce: self.recovery_nonce,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait]
impl UserEncryptedMasterKeyRepository for PgUserEncryptedMasterKeyRepository {
    type Error = PgUserEncryptedMasterKeyRepositoryError;

    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserEncryptedMasterKey>, Self::Error> {
        let row = sqlx::query_as!(
            UserEncryptedMasterKeyRow,
            r#"
            SELECT user_id, auth_type, encrypted_umk, umk_nonce, salt, kdf_type,
                   kdf_params as "kdf_params: sqlx::types::Json<KdfParams>",
                   auth_key_hash, recovery_encrypted_umk, recovery_nonce, created_at, updated_at
            FROM user_encrypted_master_keys
            WHERE user_id = $1
            "#,
            user_id.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_key()).transpose()
    }

    async fn save(&self, key: &UserEncryptedMasterKey) -> Result<(), Self::Error> {
        let kdf_params_json = key
            .kdf_params
            .as_ref()
            .map(|p| serde_json::to_value(p).unwrap());

        sqlx::query!(
            r#"
            INSERT INTO user_encrypted_master_keys (
                user_id, auth_type, encrypted_umk, umk_nonce, salt, kdf_type, kdf_params,
                auth_key_hash, recovery_encrypted_umk, recovery_nonce, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (user_id) DO UPDATE SET
                auth_type = EXCLUDED.auth_type,
                encrypted_umk = EXCLUDED.encrypted_umk,
                umk_nonce = EXCLUDED.umk_nonce,
                salt = EXCLUDED.salt,
                kdf_type = EXCLUDED.kdf_type,
                kdf_params = EXCLUDED.kdf_params,
                auth_key_hash = EXCLUDED.auth_key_hash,
                recovery_encrypted_umk = EXCLUDED.recovery_encrypted_umk,
                recovery_nonce = EXCLUDED.recovery_nonce,
                updated_at = EXCLUDED.updated_at
            "#,
            key.user_id.as_uuid(),
            key.auth_type.as_str(),
            key.encrypted_umk.as_deref(),
            key.umk_nonce.as_deref(),
            key.salt.as_deref(),
            key.kdf_type.map(|t| t.as_str()) as Option<&str>,
            kdf_params_json as Option<serde_json::Value>,
            key.auth_key_hash.as_deref(),
            &key.recovery_encrypted_umk,
            &key.recovery_nonce,
            key.created_at,
            key.updated_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM user_encrypted_master_keys WHERE user_id = $1",
            user_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ UserEncryptedIdentityKey Repository ============

pg_repo_struct!(PgUserEncryptedIdentityKeyRepository);
pg_repo_error!(PgUserEncryptedIdentityKeyRepositoryError);

#[derive(sqlx::FromRow)]
struct UserEncryptedIdentityKeyRow {
    user_id: Uuid,
    encrypted_ecdh_private: Vec<u8>,
    encrypted_ecdh_private_nonce: Vec<u8>,
    encrypted_signing_private: Vec<u8>,
    encrypted_signing_private_nonce: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserEncryptedIdentityKeyRow> for UserEncryptedIdentityKey {
    fn from(row: UserEncryptedIdentityKeyRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            encrypted_ecdh_private: row.encrypted_ecdh_private,
            encrypted_ecdh_private_nonce: row.encrypted_ecdh_private_nonce,
            encrypted_signing_private: row.encrypted_signing_private,
            encrypted_signing_private_nonce: row.encrypted_signing_private_nonce,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserEncryptedIdentityKeyRepository for PgUserEncryptedIdentityKeyRepository {
    type Error = PgUserEncryptedIdentityKeyRepositoryError;

    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserEncryptedIdentityKey>, Self::Error> {
        let row = sqlx::query_as!(
            UserEncryptedIdentityKeyRow,
            r#"
            SELECT user_id, encrypted_ecdh_private, encrypted_ecdh_private_nonce,
                   encrypted_signing_private, encrypted_signing_private_nonce, created_at, updated_at
            FROM user_encrypted_identity_keys
            WHERE user_id = $1
            "#,
            user_id.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(UserEncryptedIdentityKey::from))
    }

    async fn save(&self, key: &UserEncryptedIdentityKey) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO user_encrypted_identity_keys (
                user_id, encrypted_ecdh_private, encrypted_ecdh_private_nonce,
                encrypted_signing_private, encrypted_signing_private_nonce, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id) DO UPDATE SET
                encrypted_ecdh_private = EXCLUDED.encrypted_ecdh_private,
                encrypted_ecdh_private_nonce = EXCLUDED.encrypted_ecdh_private_nonce,
                encrypted_signing_private = EXCLUDED.encrypted_signing_private,
                encrypted_signing_private_nonce = EXCLUDED.encrypted_signing_private_nonce,
                updated_at = EXCLUDED.updated_at
            "#,
            key.user_id.as_uuid(),
            &key.encrypted_ecdh_private,
            &key.encrypted_ecdh_private_nonce,
            &key.encrypted_signing_private,
            &key.encrypted_signing_private_nonce,
            key.created_at,
            key.updated_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM user_encrypted_identity_keys WHERE user_id = $1",
            user_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
