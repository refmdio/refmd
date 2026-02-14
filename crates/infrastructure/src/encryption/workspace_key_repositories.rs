//! PostgreSQL workspace and document key repository implementations

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{
    DeviceId, DocumentEncryptedKey, DocumentEncryptedKeyRepository, DocumentId, InvalidKeyVersion,
    KeyVersion, WorkspaceEncryptedKey, WorkspaceEncryptedKeyRepository, WorkspaceId,
    WorkspaceKekBackup, WorkspaceKekBackupRepository,
};
use domain::identity::UserId;
use uuid::Uuid;

/// Shared transaction pattern: optionally deactivate existing active rows,
/// then upsert the new row, all within a single transaction.
macro_rules! save_with_active_tx {
    ($pool:expr, $is_active:expr, $deactivate:expr, $upsert:expr) => {{
        let mut tx = $pool.begin().await?;
        if $is_active {
            $deactivate.execute(&mut *tx).await?;
        }
        $upsert.execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }};
}

// ============ WorkspaceEncryptedKey Repository ============

pg_repo_struct!(PgWorkspaceEncryptedKeyRepository);
pg_repo_error!(PgWorkspaceEncryptedKeyRepositoryError, InvalidKeyVersion(#[from] InvalidKeyVersion));

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

impl TryFrom<WorkspaceEncryptedKeyRow> for WorkspaceEncryptedKey {
    type Error = InvalidKeyVersion;

    fn try_from(row: WorkspaceEncryptedKeyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            user_id: UserId::from_uuid(row.user_id),
            device_id: DeviceId::from_uuid(row.device_id),
            sender_device_id: DeviceId::from_uuid(row.sender_device_id),
            key_version: KeyVersion::new(row.key_version)?,
            encrypted_kek: row.encrypted_kek,
            nonce: row.nonce,
            is_active: row.is_active,
            created_at: row.created_at,
        })
    }
}

#[async_trait]
impl WorkspaceEncryptedKeyRepository for PgWorkspaceEncryptedKeyRepository {
    type Error = PgWorkspaceEncryptedKeyRepositoryError;

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as!(
            WorkspaceEncryptedKeyRow,
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1
            ORDER BY key_version DESC
            "#,
            workspace_id.as_uuid() as _,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(WorkspaceEncryptedKey::try_from)
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn find_by_workspace_and_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as!(
            WorkspaceEncryptedKeyRow,
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3
            ORDER BY key_version DESC
            "#,
            workspace_id.as_uuid() as _,
            user_id.as_uuid() as _,
            device_id.as_uuid() as _,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(WorkspaceEncryptedKey::try_from)
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn find_active_by_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<WorkspaceEncryptedKey>, Self::Error> {
        let row = sqlx::query_as!(
            WorkspaceEncryptedKeyRow,
            r#"
            SELECT workspace_id, user_id, device_id, sender_device_id, key_version,
                   encrypted_kek, nonce, is_active, created_at
            FROM workspace_encrypted_keys
            WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3 AND is_active = TRUE
            ORDER BY key_version DESC
            LIMIT 1
            "#,
            workspace_id.as_uuid() as _,
            user_id.as_uuid() as _,
            device_id.as_uuid() as _,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceEncryptedKey::try_from).transpose()?)
    }

    async fn save(&self, key: &WorkspaceEncryptedKey) -> Result<(), Self::Error> {
        save_with_active_tx!(
            self.pool,
            key.is_active,
            sqlx::query!(
                r#"
                UPDATE workspace_encrypted_keys
                SET is_active = FALSE
                WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3 AND is_active = TRUE
                "#,
                key.workspace_id.as_uuid() as _,
                key.user_id.as_uuid() as _,
                key.device_id.as_uuid() as _,
            ),
            sqlx::query!(
                r#"
                INSERT INTO workspace_encrypted_keys (
                    workspace_id, user_id, device_id, sender_device_id, key_version,
                    encrypted_kek, nonce, is_active, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (workspace_id, user_id, device_id, key_version) DO UPDATE SET
                    encrypted_kek = EXCLUDED.encrypted_kek,
                    nonce = EXCLUDED.nonce,
                    sender_device_id = EXCLUDED.sender_device_id,
                    is_active = EXCLUDED.is_active
                "#,
                key.workspace_id.as_uuid() as _,
                key.user_id.as_uuid() as _,
                key.device_id.as_uuid() as _,
                key.sender_device_id.as_uuid() as _,
                key.key_version.as_i32() as _,
                &key.encrypted_kek,
                &key.nonce,
                key.is_active,
                key.created_at,
            )
        )
    }

    async fn delete_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM workspace_encrypted_keys WHERE workspace_id = $1 AND user_id = $2",
            workspace_id.as_uuid() as _,
            user_id.as_uuid() as _,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ DocumentEncryptedKey Repository ============

pg_repo_struct!(PgDocumentEncryptedKeyRepository);
pg_repo_error!(PgDocumentEncryptedKeyRepositoryError, InvalidKeyVersion(#[from] InvalidKeyVersion));

#[derive(sqlx::FromRow)]
struct DocumentEncryptedKeyRow {
    document_id: Uuid,
    key_version: i32,
    encrypted_dek: Vec<u8>,
    nonce: Vec<u8>,
    is_active: bool,
    created_at: DateTime<Utc>,
}

impl TryFrom<DocumentEncryptedKeyRow> for DocumentEncryptedKey {
    type Error = InvalidKeyVersion;

    fn try_from(row: DocumentEncryptedKeyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            document_id: DocumentId::from_uuid(row.document_id),
            key_version: KeyVersion::new(row.key_version)?,
            encrypted_dek: row.encrypted_dek,
            nonce: row.nonce,
            is_active: row.is_active,
            created_at: row.created_at,
        })
    }
}

#[async_trait]
impl DocumentEncryptedKeyRepository for PgDocumentEncryptedKeyRepository {
    type Error = PgDocumentEncryptedKeyRepositoryError;

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentEncryptedKey>, Self::Error> {
        let rows = sqlx::query_as!(
            DocumentEncryptedKeyRow,
            r#"
            SELECT document_id, key_version, encrypted_dek, nonce, is_active, created_at
            FROM document_encrypted_keys
            WHERE document_id = $1
            ORDER BY key_version DESC
            "#,
            document_id.as_uuid() as _,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(DocumentEncryptedKey::try_from)
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<DocumentEncryptedKey>, Self::Error> {
        let row = sqlx::query_as!(
            DocumentEncryptedKeyRow,
            r#"
            SELECT document_id, key_version, encrypted_dek, nonce, is_active, created_at
            FROM document_encrypted_keys
            WHERE document_id = $1 AND is_active = TRUE
            ORDER BY key_version DESC
            LIMIT 1
            "#,
            document_id.as_uuid() as _,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentEncryptedKey::try_from).transpose()?)
    }

    async fn save(&self, key: &DocumentEncryptedKey) -> Result<(), Self::Error> {
        save_with_active_tx!(
            self.pool,
            key.is_active,
            sqlx::query!(
                r#"
                UPDATE document_encrypted_keys
                SET is_active = FALSE
                WHERE document_id = $1 AND is_active = TRUE
                "#,
                key.document_id.as_uuid() as _,
            ),
            sqlx::query!(
                r#"
                INSERT INTO document_encrypted_keys (
                    document_id, key_version, encrypted_dek, nonce, is_active, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (document_id, key_version) DO UPDATE SET
                    encrypted_dek = EXCLUDED.encrypted_dek,
                    nonce = EXCLUDED.nonce,
                    is_active = EXCLUDED.is_active
                "#,
                key.document_id.as_uuid() as _,
                key.key_version.as_i32() as _,
                &key.encrypted_dek,
                &key.nonce,
                key.is_active,
                key.created_at,
            )
        )
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM document_encrypted_keys WHERE document_id = $1",
            document_id.as_uuid() as _,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ WorkspaceKekBackup Repository ============

pg_repo_struct!(PgWorkspaceKekBackupRepository);
pg_repo_error!(PgWorkspaceKekBackupRepositoryError, InvalidKeyVersion(#[from] InvalidKeyVersion));

#[derive(sqlx::FromRow)]
struct WorkspaceKekBackupRow {
    workspace_id: Uuid,
    user_id: Uuid,
    key_version: i32,
    encrypted_kek: Vec<u8>,
    nonce: Vec<u8>,
    is_active: bool,
    created_at: DateTime<Utc>,
}

impl TryFrom<WorkspaceKekBackupRow> for WorkspaceKekBackup {
    type Error = InvalidKeyVersion;

    fn try_from(row: WorkspaceKekBackupRow) -> Result<Self, Self::Error> {
        Ok(Self {
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            user_id: UserId::from_uuid(row.user_id),
            key_version: KeyVersion::new(row.key_version)?,
            encrypted_kek: row.encrypted_kek,
            nonce: row.nonce,
            is_active: row.is_active,
            created_at: row.created_at,
        })
    }
}

#[async_trait]
impl WorkspaceKekBackupRepository for PgWorkspaceKekBackupRepository {
    type Error = PgWorkspaceKekBackupRepositoryError;

    async fn find_active_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<Option<WorkspaceKekBackup>, Self::Error> {
        let row = sqlx::query_as!(
            WorkspaceKekBackupRow,
            r#"
            SELECT workspace_id, user_id, key_version, encrypted_kek, nonce, is_active, created_at
            FROM workspace_kek_backups
            WHERE workspace_id = $1 AND user_id = $2 AND is_active = TRUE
            LIMIT 1
            "#,
            workspace_id.as_uuid() as _,
            user_id.as_uuid() as _,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceKekBackup::try_from).transpose()?)
    }

    async fn save(&self, backup: &WorkspaceKekBackup) -> Result<(), Self::Error> {
        save_with_active_tx!(
            self.pool,
            backup.is_active,
            sqlx::query!(
                r#"
                UPDATE workspace_kek_backups
                SET is_active = FALSE
                WHERE workspace_id = $1 AND user_id = $2 AND is_active = TRUE
                "#,
                backup.workspace_id.as_uuid() as _,
                backup.user_id.as_uuid() as _,
            ),
            sqlx::query!(
                r#"
                INSERT INTO workspace_kek_backups (
                    workspace_id, user_id, key_version, encrypted_kek, nonce, is_active, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (workspace_id, user_id, key_version) DO UPDATE SET
                    encrypted_kek = EXCLUDED.encrypted_kek,
                    nonce = EXCLUDED.nonce,
                    is_active = EXCLUDED.is_active
                "#,
                backup.workspace_id.as_uuid() as _,
                backup.user_id.as_uuid() as _,
                backup.key_version.as_i32() as _,
                &backup.encrypted_kek,
                &backup.nonce,
                backup.is_active,
                backup.created_at,
            )
        )
    }
}
