//! Role update service trait
//!
//! Defines the interface for atomic role updates (metadata + permission overrides).
//! The infrastructure layer provides the transactional implementation.

use async_trait::async_trait;
use domain::workspace::{RoleId, WorkspaceId};
use thiserror::Error;

/// Role update errors
#[derive(Debug, Error)]
pub enum RoleUpdateError {
    #[error("role not found")]
    RoleNotFound,

    #[error("database error: {0}")]
    Database(String),
}

/// Role update service trait
///
/// Atomically updates role metadata (name, is_default swap) and permission
/// overrides in a single transaction so that partial-commit is impossible.
#[async_trait]
pub trait RoleUpdateService: Send + Sync {
    /// Atomically update role name, optionally swap default, and replace permission overrides.
    ///
    /// - If `new_name` is `Some`, updates the role's name.
    /// - If `swap_default` is `true`, swaps the workspace default to this role.
    /// - `permission_overrides` replaces all existing overrides for the role.
    ///   If `None`, permission overrides are not modified.
    async fn update_role_atomic(
        &self,
        workspace_id: WorkspaceId,
        role_id: RoleId,
        new_name: Option<&str>,
        swap_default: bool,
        permission_overrides: Option<&[(String, bool)]>,
    ) -> Result<(), RoleUpdateError>;
}
