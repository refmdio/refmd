//! Migration repository port for E2EE migration processing.
//!
//! This repository provides read-only access to existing plaintext data
//! during the E2EE migration process. Write operations are handled through
//! the transactional interface in `migration_tx_runner`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

/// Document information for migration.
#[derive(Debug, Clone)]
pub struct MigrationDocument {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
}

/// File information for migration.
#[derive(Debug, Clone)]
pub struct MigrationFile {
    pub id: Uuid,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub filename: String,
    pub content_type: Option<String>,
    pub storage_path: String,
}

/// Latest snapshot information.
#[derive(Debug, Clone)]
pub struct MigrationSnapshot {
    pub document_id: Uuid,
    pub version: i64,
    pub data: Vec<u8>,
    pub seq_at_snapshot: Option<i64>,
}

/// Repository trait for E2EE migration read operations.
///
/// This trait provides read-only access to plaintext data that needs
/// to be encrypted during migration. Write operations are performed
/// through `MigrationRepositoryTx` within a transaction.
#[async_trait]
pub trait MigrationRepository: Send + Sync {
    /// List all documents owned by or accessible to a user.
    ///
    /// Returns documents from all workspaces where the user is a member,
    /// filtered to only include documents that haven't been encrypted yet.
    async fn list_user_documents(&self, user_id: Uuid) -> PortResult<Vec<MigrationDocument>>;

    /// List all files associated with a user's documents.
    ///
    /// Returns files that haven't been encrypted yet.
    async fn list_user_files(&self, user_id: Uuid) -> PortResult<Vec<MigrationFile>>;
}
