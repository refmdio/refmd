//! PostgreSQL workspace and document key repository implementations

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{
    DeviceId, DocumentEncryptedKey, DocumentEncryptedKeyRepository, DocumentId, KeyVersion,
    WorkspaceEncryptedKey, WorkspaceEncryptedKeyRepository, WorkspaceId,
};
use domain::identity::UserId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

// ============ WorkspaceEncryptedKey Repository ============

/// PostgreSQL workspace encrypted key repository
#[derive(Clone)]
pub struct PgWorkspaceEncryptedKeyRepository {
    pool: PgPool,
}

impl PgWorkspaceEncryptedKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceEncryptedKeyRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct WorkspaceEncryptedKeyRow {
    workspace_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    sender_device_id: Uuid,
    key_version: i32,
    encrypted_kek: Vec<u8>,
    nonce: Vec<u8>,
    is_active: bool,
    created_at: DateTime<Utc>,
}

impl From<WorkspaceEncryptedKeyRow> for WorkspaceEncryptedKey {
    fn from(row: WorkspaceEncryptedKeyRow) -> Self {
        Self {
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            user_id: UserId::from_uuid(row.user_id),
            device_id: DeviceId::from_uuid(row.device_id),
            sender_device_id: DeviceId::from_uuid(row.sender_device_id),
            key_version: KeyVersion::new(row.key_version),
            encrypted_kek: row.encrypted_kek,
            nonce: row.nonce,
            is_active: row.is_active,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl WorkspaceEncryptedKeyRepository for PgWorkspaceEncryptedKeyRepository {
    type Error = PgWorkspaceEncryptedKeyRepositoryError;

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceEncryptedKeyRow>(
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1
            ORDER BY key_version DESC
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceEncryptedKey::from).collect())
    }

    async fn find_by_workspace_and_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceEncryptedKeyRow>(
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3
            ORDER BY key_version DESC
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(device_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceEncryptedKey::from).collect())
    }

    async fn find_active_by_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<WorkspaceEncryptedKey>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceEncryptedKeyRow>(
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3 AND is_active = TRUE
            ORDER BY key_version DESC
            LIMIT 1
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(device_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceEncryptedKey::from))
    }

    async fn save(&self, key: &WorkspaceEncryptedKey) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspace_encrypted_keys (
                workspace_id, user_id, device_id, sender_device_id, key_version,
                encrypted_kek, nonce, is_active, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (workspace_id, user_id, device_id, key_version) DO UPDATE SET
                is_active = EXCLUDED.is_active
            "#,
        )
        .bind(key.workspace_id.as_uuid())
        .bind(key.user_id.as_uuid())
        .bind(key.device_id.as_uuid())
        .bind(key.sender_device_id.as_uuid())
        .bind(key.key_version.as_i32())
        .bind(&key.encrypted_kek)
        .bind(&key.nonce)
        .bind(key.is_active)
        .bind(key.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            "DELETE FROM workspace_encrypted_keys WHERE workspace_id = $1 AND user_id = $2",
        )
        .bind(workspace_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ DocumentEncryptedKey Repository ============

/// PostgreSQL document encrypted key repository
#[derive(Clone)]
pub struct PgDocumentEncryptedKeyRepository {
    pool: PgPool,
}

impl PgDocumentEncryptedKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentEncryptedKeyRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct DocumentEncryptedKeyRow {
    document_id: Uuid,
    key_version: i32,
    encrypted_dek: Vec<u8>,
    nonce: Vec<u8>,
    is_active: bool,
    created_at: DateTime<Utc>,
}

impl From<DocumentEncryptedKeyRow> for DocumentEncryptedKey {
    fn from(row: DocumentEncryptedKeyRow) -> Self {
        Self {
            document_id: DocumentId::from_uuid(row.document_id),
            key_version: KeyVersion::new(row.key_version),
            encrypted_dek: row.encrypted_dek,
            nonce: row.nonce,
            is_active: row.is_active,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DocumentEncryptedKeyRepository for PgDocumentEncryptedKeyRepository {
    type Error = PgDocumentEncryptedKeyRepositoryError;

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentEncryptedKeyRow>(
            r#"
            SELECT document_id, key_version, encrypted_dek, nonce, is_active, created_at
            FROM document_encrypted_keys
            WHERE document_id = $1
            ORDER BY key_version DESC
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentEncryptedKey::from).collect())
    }

    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<DocumentEncryptedKey>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentEncryptedKeyRow>(
            r#"
            SELECT document_id, key_version, encrypted_dek, nonce, is_active, created_at
            FROM document_encrypted_keys
            WHERE document_id = $1 AND is_active = TRUE
            ORDER BY key_version DESC
            LIMIT 1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentEncryptedKey::from))
    }

    async fn save(&self, key: &DocumentEncryptedKey) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO document_encrypted_keys (
                document_id, key_version, encrypted_dek, nonce, is_active, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (document_id, key_version) DO UPDATE SET
                is_active = EXCLUDED.is_active
            "#,
        )
        .bind(key.document_id.as_uuid())
        .bind(key.key_version.as_i32())
        .bind(&key.encrypted_dek)
        .bind(&key.nonce)
        .bind(key.is_active)
        .bind(key.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_encrypted_keys WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
