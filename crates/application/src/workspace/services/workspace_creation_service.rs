//! Workspace creation service trait
//!
//! Defines the interface for transactional workspace creation.
//! The infrastructure layer provides the implementation.

use async_trait::async_trait;
use domain::workspace::{Workspace, WorkspaceMember, WorkspaceRole};
use thiserror::Error;

/// Data for workspace creation (passed to the service)
pub struct WorkspaceCreationData {
    pub workspace: Workspace,
    pub owner_role: WorkspaceRole,
    pub admin_role: WorkspaceRole,
    pub editor_role: WorkspaceRole,
    pub viewer_role: WorkspaceRole,
    pub member: WorkspaceMember,
}

/// Workspace creation service error
#[derive(Debug, Error)]
pub enum WorkspaceCreationServiceError {
    #[error("workspace slug already exists")]
    SlugConflict,

    #[error("database error: {0}")]
    Database(String),

    #[error("transaction failed: {0}")]
    TransactionFailed(String),
}

/// Workspace creation service trait for transactional workspace creation
///
/// All entities (workspace, 4 roles, owner member) are persisted
/// in a single atomic transaction.
#[async_trait]
pub trait WorkspaceCreationService: Send + Sync {
    async fn create_atomic(
        &self,
        data: WorkspaceCreationData,
    ) -> Result<(), WorkspaceCreationServiceError>;
}
