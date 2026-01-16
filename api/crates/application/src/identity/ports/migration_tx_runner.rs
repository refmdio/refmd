//! Transaction runner for E2EE migration operations.
//!
//! This module provides transactional support for the migration process,
//! ensuring that all database operations are atomic.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use anyhow::anyhow;
use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

use super::migration_repository::MigrationSnapshot;

// ============================================================================
// Type aliases for boxed futures
// ============================================================================

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxedTxResult = Box<dyn Any + Send>;
pub type MigrationTxFuture<'tx> = BoxFuture<'tx, anyhow::Result<BoxedTxResult>>;
pub type MigrationTxFn =
    Box<dyn for<'tx> FnOnce(&'tx mut dyn MigrationTx) -> MigrationTxFuture<'tx> + Send>;

// ============================================================================
// Transaction context trait
// ============================================================================

/// Transaction context for migration operations.
///
/// Provides access to all repositories needed during migration,
/// all operating within the same database transaction.
pub trait MigrationTx: Send {
    /// Access to migration-specific repository operations.
    fn migration(&mut self) -> &mut dyn MigrationRepositoryTx;

    /// Access to document keys repository.
    fn document_keys(&mut self) -> &mut dyn DocumentKeysRepositoryTx;

    /// Access to workspace keys repository.
    fn workspace_keys(&mut self) -> &mut dyn WorkspaceKeysRepositoryTx;

    /// Access to user keys repository.
    fn user_keys(&mut self) -> &mut dyn UserKeysRepositoryTx;
}

// ============================================================================
// Transactional repository traits
// ============================================================================

/// Migration repository operations that run within a transaction.
#[async_trait]
pub trait MigrationRepositoryTx: Send {
    /// Update a document with encrypted title.
    async fn update_encrypted_title(
        &mut self,
        document_id: Uuid,
        encrypted_title: &[u8],
        nonce: &[u8],
    ) -> PortResult<()>;

    /// Create or update an encrypted snapshot for a document.
    async fn upsert_encrypted_snapshot(
        &mut self,
        document_id: Uuid,
        encrypted_snapshot: &[u8],
        nonce: &[u8],
        seq_at_snapshot: i64,
    ) -> PortResult<()>;

    /// Delete all plaintext updates for a document.
    async fn clear_plaintext_updates(&mut self, document_id: Uuid) -> PortResult<u64>;

    /// Update a file's metadata with encrypted values.
    async fn update_encrypted_file_metadata(
        &mut self,
        file_id: Uuid,
        encrypted_metadata: &[u8],
        nonce: &[u8],
        encrypted_hash: &str,
    ) -> PortResult<()>;

    /// Clear plaintext title from a document after encryption.
    async fn clear_plaintext_title(&mut self, document_id: Uuid) -> PortResult<()>;

    /// Clear plaintext metadata from a file after encryption.
    async fn clear_plaintext_file_metadata(&mut self, file_id: Uuid) -> PortResult<()>;

    /// Get the latest Yjs snapshot for a document.
    async fn get_document_snapshot(
        &mut self,
        document_id: Uuid,
    ) -> PortResult<Option<MigrationSnapshot>>;

    /// Get the maximum sequence number for a document's updates.
    async fn get_document_max_seq(&mut self, document_id: Uuid) -> PortResult<Option<i64>>;
}

/// Document keys repository operations that run within a transaction.
#[async_trait]
pub trait DocumentKeysRepositoryTx: Send {
    /// Store or update an encrypted DEK for a document.
    async fn upsert_encrypted_dek(
        &mut self,
        document_id: Uuid,
        encrypted_dek: &[u8],
        nonce: &[u8],
        key_version: i32,
    ) -> PortResult<()>;
}

/// Workspace keys repository operations that run within a transaction.
#[async_trait]
pub trait WorkspaceKeysRepositoryTx: Send {
    /// Store or update an encrypted KEK for a workspace member.
    async fn upsert_encrypted_kek(
        &mut self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: &[u8],
        key_version: i32,
    ) -> PortResult<()>;
}

/// User keys repository operations that run within a transaction.
#[async_trait]
pub trait UserKeysRepositoryTx: Send {
    /// Mark encryption setup as completed for a user.
    async fn mark_encryption_setup_completed(&mut self, user_id: Uuid) -> PortResult<()>;

    /// Check if encryption setup is completed for a user.
    async fn is_encryption_setup_completed(&mut self, user_id: Uuid) -> PortResult<bool>;
}

// ============================================================================
// Transaction runner trait
// ============================================================================

/// Runner for executing migration operations within a transaction.
#[async_trait]
pub trait MigrationTxRunner: Send + Sync {
    /// Execute a function within a database transaction.
    ///
    /// The transaction is committed if the function returns Ok,
    /// and rolled back if it returns Err.
    async fn run_boxed(&self, f: MigrationTxFn) -> anyhow::Result<BoxedTxResult>;
}

// ============================================================================
// Helper function
// ============================================================================

/// Execute a migration operation within a transaction.
///
/// This is a type-safe wrapper around `MigrationTxRunner::run_boxed`.
pub async fn run_migration_tx<T, F>(runner: &dyn MigrationTxRunner, f: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx mut dyn MigrationTx) -> BoxFuture<'tx, anyhow::Result<T>>
        + Send
        + 'static,
{
    let mut f = Some(f);
    let result = runner
        .run_boxed(Box::new(move |tx| {
            let f = f
                .take()
                .expect("MigrationTx closure must be called exactly once");
            Box::pin(async move {
                let out = f(tx).await?;
                Ok(Box::new(out) as BoxedTxResult)
            })
        }))
        .await?;

    result
        .downcast::<T>()
        .map(|v| *v)
        .map_err(|_| anyhow!("migration tx runner output type mismatch"))
}
