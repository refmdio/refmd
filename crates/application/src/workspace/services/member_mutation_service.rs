//! Member mutation service trait
//!
//! Defines the interface for transactional member operations that require
//! Owner continuity guarantees (SELECT ... FOR UPDATE on owner rows).
//!
//! Per design doc (workspace.md § Owner continuity):
//! 1. Lock owner member rows with SELECT ... FOR UPDATE
//! 2. Re-count owners after acquiring lock
//! 3. Re-verify operator's own role (may have been demoted before lock)
//! 4. Perform DELETE/UPDATE atomically

use async_trait::async_trait;
use domain::identity::UserId;
use domain::workspace::{RoleId, WorkspaceId};
use thiserror::Error;

/// Member mutation errors (transactional)
#[derive(Debug, Error)]
pub enum MemberMutationError {
    #[error("cannot remove the last owner of the workspace")]
    LastOwner,

    #[error("operator is no longer an owner (demoted during lock wait)")]
    OperatorDemoted,

    #[error("target member not found")]
    TargetNotFound,

    #[error("target role not found")]
    TargetRoleNotFound,

    #[error("member's role changed concurrently (possible promotion to Owner)")]
    RoleConflict,

    #[error("database error: {0}")]
    Database(String),
}

/// Member mutation service trait
///
/// Performs member mutations atomically with Owner continuity guarantees.
/// Owner-targeting methods:
/// 1. SELECT ... FOR UPDATE on workspace_members JOIN workspace_roles WHERE base_role = 'owner'
/// 2. Re-count owners
/// 3. Re-verify operator's role (must still be Owner if target is Owner)
/// 4. Execute the mutation within the same transaction
#[async_trait]
pub trait MemberMutationService: Send + Sync {
    /// Remove a member atomically with Owner continuity check.
    /// Called only when the target is an Owner (non-Owner removals don't need FOR UPDATE).
    async fn remove_owner_member(
        &self,
        workspace_id: WorkspaceId,
        operator_user_id: UserId,
        target_user_id: UserId,
    ) -> Result<(), MemberMutationError>;

    /// Remove a non-Owner member with a conditional DELETE that includes the
    /// expected role_id. If the member was concurrently promoted to a different
    /// role (especially Owner), the DELETE will affect 0 rows and return
    /// `MemberMutationError::RoleConflict`.
    async fn remove_non_owner_member(
        &self,
        workspace_id: WorkspaceId,
        target_user_id: UserId,
        expected_role_id: RoleId,
    ) -> Result<(), MemberMutationError>;

    /// Change an Owner member's role atomically with Owner continuity check.
    /// Called only when demoting an Owner (Owner→non-Owner transitions need FOR UPDATE).
    async fn demote_owner_member(
        &self,
        workspace_id: WorkspaceId,
        operator_user_id: UserId,
        target_user_id: UserId,
        new_role_id: RoleId,
    ) -> Result<(), MemberMutationError>;

    /// Change a non-Owner member's role with a conditional UPDATE that includes the
    /// expected current role_id. If the member was concurrently promoted to a different
    /// role (especially Owner), the UPDATE will affect 0 rows and return
    /// `MemberMutationError::RoleConflict`.
    async fn change_non_owner_role(
        &self,
        workspace_id: WorkspaceId,
        target_user_id: UserId,
        expected_role_id: RoleId,
        new_role_id: RoleId,
    ) -> Result<(), MemberMutationError>;
}
