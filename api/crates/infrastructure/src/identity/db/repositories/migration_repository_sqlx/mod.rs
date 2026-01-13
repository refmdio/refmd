//! SQLx implementation of the migration repository.

use async_trait::async_trait;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::identity::ports::migration_repository::{
    MigrationDocument, MigrationFile, MigrationRepository, MigrationSnapshot,
};

/// SQLx implementation of the migration repository.
///
/// This provides read-only access to plaintext data for migration.
pub struct SqlxMigrationRepository {
    pool: PgPool,
}

impl SqlxMigrationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the pool for transaction creation.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl MigrationRepository for SqlxMigrationRepository {
    async fn list_user_documents(&self, user_id: Uuid) -> PortResult<Vec<MigrationDocument>> {
        let out: anyhow::Result<Vec<MigrationDocument>> = async {
            // Get all documents from workspaces where the user is a member
            let rows = sqlx::query(
                r#"
                SELECT d.id, d.workspace_id, d.title, d.created_at
                FROM documents d
                INNER JOIN workspace_members wm ON d.workspace_id = wm.workspace_id
                WHERE wm.user_id = $1
                  AND d.encrypted_title IS NULL
                ORDER BY d.created_at
                "#,
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            let documents = rows
                .into_iter()
                .map(|row| MigrationDocument {
                    id: row.get("id"),
                    workspace_id: row.get("workspace_id"),
                    title: row.get("title"),
                    created_at: row.get("created_at"),
                })
                .collect();

            Ok(documents)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_user_files(&self, user_id: Uuid) -> PortResult<Vec<MigrationFile>> {
        let out: anyhow::Result<Vec<MigrationFile>> = async {
            // Get all plaintext files (not yet encrypted) from workspaces where the user is a member
            let rows = sqlx::query(
                r#"
                SELECT f.id, f.document_id, d.workspace_id, f.filename, f.content_type, f.storage_path
                FROM files f
                INNER JOIN documents d ON f.document_id = d.id
                INNER JOIN workspace_members wm ON d.workspace_id = wm.workspace_id
                WHERE wm.user_id = $1
                  AND f.encrypted_metadata IS NULL
                ORDER BY f.created_at
                "#,
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            let files = rows
                .into_iter()
                .map(|row| MigrationFile {
                    id: row.get("id"),
                    document_id: row.get("document_id"),
                    workspace_id: row.get("workspace_id"),
                    filename: row.get("filename"),
                    content_type: row.get("content_type"),
                    storage_path: row.get("storage_path"),
                })
                .collect();

            Ok(files)
        }
        .await;
        out.map_err(Into::into)
    }
}

// ============================================================================
// Transactional operations
// ============================================================================

impl SqlxMigrationRepository {
    /// Update a document with encrypted title (within transaction).
    pub async fn update_encrypted_title_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
        encrypted_title: &[u8],
        nonce: &[u8],
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE documents
            SET encrypted_title = $2,
                encrypted_title_nonce = $3,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(document_id)
        .bind(encrypted_title)
        .bind(nonce)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Create or update an encrypted snapshot (within transaction).
    pub async fn upsert_encrypted_snapshot_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
        encrypted_snapshot: &[u8],
        nonce: &[u8],
        seq_at_snapshot: i64,
    ) -> anyhow::Result<()> {
        // Get the next version number
        let next_version: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(MAX(version), 0) + 1
            FROM document_snapshots
            WHERE document_id = $1
            "#,
        )
        .bind(document_id)
        .fetch_one(tx.as_mut())
        .await?;

        // Insert new encrypted snapshot
        sqlx::query(
            r#"
            INSERT INTO document_snapshots (document_id, version, snapshot, nonce, seq_at_snapshot, created_at)
            VALUES ($1, $2, $3, $4, $5, now())
            "#,
        )
        .bind(document_id)
        .bind(next_version)
        .bind(encrypted_snapshot)
        .bind(nonce)
        .bind(seq_at_snapshot)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Delete all plaintext updates for a document (within transaction).
    pub async fn clear_plaintext_updates_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
    ) -> anyhow::Result<u64> {
        // Delete all plaintext updates (those without nonce)
        let result = sqlx::query(
            r#"
            DELETE FROM document_updates
            WHERE document_id = $1
              AND nonce IS NULL
            "#,
        )
        .bind(document_id)
        .execute(tx.as_mut())
        .await?;

        Ok(result.rows_affected())
    }

    /// Update a file's metadata with encrypted values (within transaction).
    pub async fn update_encrypted_file_metadata_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        file_id: Uuid,
        encrypted_metadata: &[u8],
        nonce: &[u8],
        encrypted_hash: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE files
            SET encrypted_metadata = $2,
                encrypted_metadata_nonce = $3,
                encrypted_hash = $4,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(file_id)
        .bind(encrypted_metadata)
        .bind(nonce)
        .bind(encrypted_hash)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Clear plaintext title from a document (within transaction).
    pub async fn clear_plaintext_title_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE documents
            SET title = '[encrypted]',
                updated_at = now()
            WHERE id = $1
              AND encrypted_title IS NOT NULL
            "#,
        )
        .bind(document_id)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Clear plaintext metadata from a file (within transaction).
    pub async fn clear_plaintext_file_metadata_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        file_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE files
            SET filename = '[encrypted]',
                content_type = NULL,
                updated_at = now()
            WHERE id = $1
              AND encrypted_metadata IS NOT NULL
            "#,
        )
        .bind(file_id)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Get the latest Yjs snapshot for a document (within transaction).
    pub async fn get_document_snapshot_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
    ) -> anyhow::Result<Option<MigrationSnapshot>> {
        let row = sqlx::query(
            r#"
            SELECT document_id, version, snapshot, seq_at_snapshot
            FROM document_snapshots
            WHERE document_id = $1
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(document_id)
        .fetch_optional(tx.as_mut())
        .await?;

        Ok(row.map(|row| MigrationSnapshot {
            document_id: row.get("document_id"),
            version: row.get("version"),
            data: row.get("snapshot"),
            seq_at_snapshot: row.get("seq_at_snapshot"),
        }))
    }

    /// Get the maximum sequence number for a document's updates (within transaction).
    pub async fn get_document_max_seq_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
    ) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT MAX(seq) as max_seq
            FROM document_updates
            WHERE document_id = $1
            "#,
        )
        .bind(document_id)
        .fetch_one(tx.as_mut())
        .await?;

        Ok(row.get("max_seq"))
    }
}
