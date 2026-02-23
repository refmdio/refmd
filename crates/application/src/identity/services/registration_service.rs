//! Registration service trait
//!
//! Defines the interface for transactional user registration.
//! The infrastructure layer provides the implementation.

use async_trait::async_trait;
use domain::encryption::{
    Device, UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
};
use domain::identity::{User, UserSettings};
use domain::workspace::{Workspace, WorkspaceMember, WorkspaceRole};
use thiserror::Error;

/// Data for user registration (passed to the service)
pub struct RegistrationData {
    pub user: User,
    pub settings: UserSettings,
    pub identity_public_key: UserIdentityPublicKey,
    pub encrypted_master_key: UserEncryptedMasterKey,
    pub encrypted_identity_key: UserEncryptedIdentityKey,
    pub workspace: Workspace,
    pub owner_role: WorkspaceRole,
    pub admin_role: WorkspaceRole,
    pub editor_role: WorkspaceRole,
    pub viewer_role: WorkspaceRole,
    pub member: WorkspaceMember,
    /// First device for PoP authentication
    pub device: Device,
}

/// Registration service error
#[derive(Debug, Error)]
pub enum RegistrationServiceError {
    #[error("database error: {0}")]
    Database(String),

    #[error("transaction failed: {0}")]
    TransactionFailed(String),

    #[error("unique constraint violation: {0}")]
    Conflict(String),
}

/// Registration service trait for transactional user registration
///
/// This trait defines the interface for persisting all registration data
/// in a single atomic transaction. The infrastructure layer provides
/// the implementation using database transactions.
#[async_trait]
pub trait RegistrationService: Send + Sync {
    /// Execute user registration atomically
    ///
    /// All data is persisted in a single transaction. If any part fails,
    /// the entire registration is rolled back.
    async fn register_atomic(&self, data: RegistrationData)
    -> Result<(), RegistrationServiceError>;
}
