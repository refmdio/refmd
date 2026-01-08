//! SQLx implementation of the migration transaction runner.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use application::core::ports::errors::PortResult;
use application::identity::ports::migration_repository::MigrationSnapshot;
use application::identity::ports::migration_tx_runner::{
    BoxedTxResult, DocumentKeysRepositoryTx, MigrationRepositoryTx, MigrationTx,
    MigrationTxFn, MigrationTxRunner, UserKeysRepositoryTx, WorkspaceKeysRepositoryTx,
};

use crate::core::db::PgPool;

use super::migration_repository_sqlx::SqlxMigrationRepository;

/// SQLx implementation of the migration transaction runner.
pub struct SqlxMigrationTxRunner {
    pool: PgPool,
    migration_repo: Arc<SqlxMigrationRepository>,
}

impl SqlxMigrationTxRunner {
    pub fn new(pool: PgPool, migration_repo: Arc<SqlxMigrationRepository>) -> Self {
        Self {
            pool,
            migration_repo,
        }
    }
}

#[async_trait]
impl MigrationTxRunner for SqlxMigrationTxRunner {
    async fn run_boxed(&self, f: MigrationTxFn) -> anyhow::Result<BoxedTxResult> {
        let mut tx = self.pool.begin().await?;

        let mut uow = SqlxMigrationTx {
            migration_repo: self.migration_repo.as_ref(),
            tx: &mut tx,
        };

        let result = f(&mut uow).await;
        match result {
            Ok(out) => {
                tx.commit().await?;
                Ok(out)
            }
            Err(err) => {
                tx.rollback().await.ok();
                Err(err)
            }
        }
    }
}

/// SQLx transaction context for migration.
struct SqlxMigrationTx<'repo, 'tx, 'c> {
    migration_repo: &'repo SqlxMigrationRepository,
    tx: &'tx mut Transaction<'c, Postgres>,
}

impl<'repo, 'tx, 'c> MigrationTx for SqlxMigrationTx<'repo, 'tx, 'c> {
    fn migration(&mut self) -> &mut dyn MigrationRepositoryTx {
        self
    }

    fn document_keys(&mut self) -> &mut dyn DocumentKeysRepositoryTx {
        self
    }

    fn workspace_keys(&mut self) -> &mut dyn WorkspaceKeysRepositoryTx {
        self
    }

    fn user_keys(&mut self) -> &mut dyn UserKeysRepositoryTx {
        self
    }
}

// ============================================================================
// MigrationRepositoryTx implementation
// ============================================================================

#[async_trait]
impl<'repo, 'tx, 'c> MigrationRepositoryTx for SqlxMigrationTx<'repo, 'tx, 'c> {
    async fn update_encrypted_title(
        &mut self,
        document_id: Uuid,
        encrypted_title: &[u8],
        nonce: &[u8],
    ) -> PortResult<()> {
        self.migration_repo
            .update_encrypted_title_tx(self.tx, document_id, encrypted_title, nonce)
            .await
            .map_err(Into::into)
    }

    async fn upsert_encrypted_snapshot(
        &mut self,
        document_id: Uuid,
        encrypted_snapshot: &[u8],
        nonce: &[u8],
        seq_at_snapshot: i64,
    ) -> PortResult<()> {
        self.migration_repo
            .upsert_encrypted_snapshot_tx(self.tx, document_id, encrypted_snapshot, nonce, seq_at_snapshot)
            .await
            .map_err(Into::into)
    }

    async fn clear_plaintext_updates(&mut self, document_id: Uuid) -> PortResult<u64> {
        self.migration_repo
            .clear_plaintext_updates_tx(self.tx, document_id)
            .await
            .map_err(Into::into)
    }

    async fn update_encrypted_file_metadata(
        &mut self,
        file_id: Uuid,
        encrypted_metadata: &[u8],
        nonce: &[u8],
        encrypted_hash: &str,
    ) -> PortResult<()> {
        self.migration_repo
            .update_encrypted_file_metadata_tx(self.tx, file_id, encrypted_metadata, nonce, encrypted_hash)
            .await
            .map_err(Into::into)
    }

    async fn clear_plaintext_title(&mut self, document_id: Uuid) -> PortResult<()> {
        self.migration_repo
            .clear_plaintext_title_tx(self.tx, document_id)
            .await
            .map_err(Into::into)
    }

    async fn clear_plaintext_file_metadata(&mut self, file_id: Uuid) -> PortResult<()> {
        self.migration_repo
            .clear_plaintext_file_metadata_tx(self.tx, file_id)
            .await
            .map_err(Into::into)
    }

    async fn get_document_snapshot(
        &mut self,
        document_id: Uuid,
    ) -> PortResult<Option<MigrationSnapshot>> {
        self.migration_repo
            .get_document_snapshot_tx(self.tx, document_id)
            .await
            .map_err(Into::into)
    }

    async fn get_document_max_seq(&mut self, document_id: Uuid) -> PortResult<Option<i64>> {
        self.migration_repo
            .get_document_max_seq_tx(self.tx, document_id)
            .await
            .map_err(Into::into)
    }
}

// ============================================================================
// DocumentKeysRepositoryTx implementation
// ============================================================================

#[async_trait]
impl<'repo, 'tx, 'c> DocumentKeysRepositoryTx for SqlxMigrationTx<'repo, 'tx, 'c> {
    async fn upsert_encrypted_dek(
        &mut self,
        document_id: Uuid,
        encrypted_dek: &[u8],
        nonce: &[u8],
        key_version: i32,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO document_encrypted_keys (document_id, encrypted_dek, nonce, key_version, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, now(), now())
                   ON CONFLICT (document_id)
                   DO UPDATE SET
                     encrypted_dek = EXCLUDED.encrypted_dek,
                     nonce = EXCLUDED.nonce,
                     key_version = EXCLUDED.key_version,
                     updated_at = now()"#,
            )
            .bind(document_id)
            .bind(encrypted_dek)
            .bind(nonce)
            .bind(key_version)
            .execute(self.tx.as_mut())
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}

// ============================================================================
// WorkspaceKeysRepositoryTx implementation
// ============================================================================

#[async_trait]
impl<'repo, 'tx, 'c> WorkspaceKeysRepositoryTx for SqlxMigrationTx<'repo, 'tx, 'c> {
    async fn upsert_encrypted_kek(
        &mut self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: &[u8],
        key_version: i32,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO workspace_encrypted_keys (workspace_id, user_id, encrypted_kek, key_version, created_at)
                   VALUES ($1, $2, $3, $4, now())
                   ON CONFLICT (workspace_id, user_id, key_version)
                   DO UPDATE SET
                     encrypted_kek = EXCLUDED.encrypted_kek"#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .bind(encrypted_kek)
            .bind(key_version)
            .execute(self.tx.as_mut())
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}

// ============================================================================
// UserKeysRepositoryTx implementation
// ============================================================================

#[async_trait]
impl<'repo, 'tx, 'c> UserKeysRepositoryTx for SqlxMigrationTx<'repo, 'tx, 'c> {
    async fn mark_e2ee_setup_completed(&mut self, user_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(r#"UPDATE users SET e2ee_setup_completed_at = now() WHERE id = $1"#)
                .bind(user_id)
                .execute(self.tx.as_mut())
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn is_e2ee_setup_completed(&mut self, user_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let row = sqlx::query(r#"SELECT e2ee_setup_completed_at FROM users WHERE id = $1"#)
                .bind(user_id)
                .fetch_optional(self.tx.as_mut())
                .await?;

            Ok(row
                .and_then(|r| {
                    use sqlx::Row;
                    r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("e2ee_setup_completed_at")
                        .ok()
                })
                .flatten()
                .is_some())
        }
        .await;
        out.map_err(Into::into)
    }
}
