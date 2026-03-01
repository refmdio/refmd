//! Change member role command
//!
//! Changes a member's role in a workspace. Requires member:change_role permission.
//! Prevents role escalation: cannot assign a role with higher base_role than your own.
//!
//! Owner continuity: when demoting an Owner, uses MemberMutationService
//! which performs SELECT ... FOR UPDATE to prevent concurrent race conditions.

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use crate::workspace::MemberMutationService;
use crate::workspace_events::WorkspaceEventPublisher;
use domain::identity::UserId;
use domain::workspace::{
    BaseRole, RoleId, WorkspaceId, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Change member role command
#[derive(Debug)]
pub struct ChangeMemberRoleCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub target_user_id: UserId,
    pub new_role_id: RoleId,
}

/// Change member role error
#[derive(Debug, Error)]
pub enum ChangeMemberRoleError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("target member not found")]
    TargetNotFound,

    #[error("target role not found")]
    RoleNotFound,

    #[error("target role does not belong to this workspace")]
    RoleWorkspaceMismatch,

    #[error("cannot_modify_owner")]
    CannotModifyOwner,

    #[error("role_escalation")]
    RoleEscalation,

    #[error("last_owner")]
    LastOwner,

    #[error("operator_demoted")]
    OperatorDemoted,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role_conflict")]
    RoleConflict,

    #[error("mutation service error: {0}")]
    MutationService(String),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    ChangeMemberRoleError<MR, RR, RPR>,
    not_found: [
        ChangeMemberRoleError::TargetNotFound,
        ChangeMemberRoleError::RoleNotFound,
        ChangeMemberRoleError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        ChangeMemberRoleError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        ChangeMemberRoleError::CannotModifyOwner,
        ChangeMemberRoleError::RoleEscalation,
        ChangeMemberRoleError::RoleWorkspaceMismatch,
        ChangeMemberRoleError::OperatorDemoted,
    ],
    conflict: [
        ChangeMemberRoleError::RoleConflict,
    ],
    unprocessable: [
        ChangeMemberRoleError::LastOwner,
    ],
);

/// Change member role handler
pub struct ChangeMemberRoleHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    member_mutation_service: Arc<dyn MemberMutationService>,
    workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized> ChangeMemberRoleHandler<MR, RR, RPR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        member_mutation_service: Arc<dyn MemberMutationService>,
        workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            member_mutation_service,
            workspace_event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: ChangeMemberRoleCommand,
    ) -> Result<(), ChangeMemberRoleError<MR::Error, RR::Error, RPR::Error>> {
        // 1. Permission check
        let actor = check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::MEMBER_CHANGE_ROLE,
        )
        .await
        .map_err(ChangeMemberRoleError::WorkspaceAccess)?;

        // 2. Load target member
        let target_member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.target_user_id)
            .await
            .map_err(ChangeMemberRoleError::MemberRepository)?
            .ok_or(ChangeMemberRoleError::TargetNotFound)?;

        // 3. Load target's current role
        let target_current_role = self
            .role_repo
            .find_by_id(target_member.role_id)
            .await
            .map_err(ChangeMemberRoleError::RoleRepository)?
            .ok_or(ChangeMemberRoleError::TargetNotFound)?;

        // 4. Load new role
        let new_role = self
            .role_repo
            .find_by_id(command.new_role_id)
            .await
            .map_err(ChangeMemberRoleError::RoleRepository)?
            .ok_or(ChangeMemberRoleError::RoleNotFound)?;

        // 5. Verify new role belongs to workspace
        if new_role.workspace_id != command.workspace_id {
            return Err(ChangeMemberRoleError::RoleWorkspaceMismatch);
        }

        // 6. Owner protection: only Owner can modify Owner members
        if target_current_role.base_role == BaseRole::Owner
            && actor.role.base_role != BaseRole::Owner
        {
            return Err(ChangeMemberRoleError::CannotModifyOwner);
        }

        // 7. Escalation prevention: can't assign role with base_role above yours
        if permission::privilege_level(new_role.base_role)
            > permission::privilege_level(actor.role.base_role)
        {
            return Err(ChangeMemberRoleError::RoleEscalation);
        }

        // 8. Owner demotion: use atomic service with SELECT FOR UPDATE
        if target_current_role.base_role == BaseRole::Owner
            && new_role.base_role != BaseRole::Owner
        {
            use crate::workspace::MemberMutationError;
            self.member_mutation_service
                .demote_owner_member(
                    command.workspace_id,
                    command.user_id,
                    command.target_user_id,
                    command.new_role_id,
                )
                .await
                .map_err(|e| match e {
                    MemberMutationError::LastOwner => ChangeMemberRoleError::LastOwner,
                    MemberMutationError::OperatorDemoted => ChangeMemberRoleError::OperatorDemoted,
                    MemberMutationError::TargetNotFound => ChangeMemberRoleError::TargetNotFound,
                    MemberMutationError::TargetRoleNotFound => ChangeMemberRoleError::RoleNotFound,
                    MemberMutationError::RoleConflict => ChangeMemberRoleError::RoleConflict,
                    MemberMutationError::Database(_) => {
                        ChangeMemberRoleError::MutationService(e.to_string())
                    }
                })?;

            // Best-effort: publish WS disconnect event when new role lacks document:read.
            // Effective permission check: DB override first, then base_role default (steps 7-8).
            let lost_read = self.check_lost_document_read(&new_role).await;
            if lost_read {
                self.workspace_event_publisher
                    .publish(domain::WorkspaceEvent::MemberRoleChanged {
                        workspace_id: command.workspace_id,
                        target_user_id: command.target_user_id,
                    })
                    .await;
            }

            return Ok(());
        }

        // 9. Non-owner role change: conditional update with expected role_id guard
        //    for both the target (concurrent promotion protection) and the operator
        //    (concurrent demotion protection via operator freshness guard).
        use crate::workspace::MemberMutationError;
        self.member_mutation_service
            .change_non_owner_role(
                command.workspace_id,
                command.target_user_id,
                target_member.role_id,
                command.new_role_id,
                command.user_id,
                actor.role.id,
            )
            .await
            .map_err(|e| match e {
                MemberMutationError::RoleConflict => ChangeMemberRoleError::RoleConflict,
                MemberMutationError::TargetNotFound => ChangeMemberRoleError::TargetNotFound,
                MemberMutationError::OperatorDemoted => ChangeMemberRoleError::OperatorDemoted,
                _ => ChangeMemberRoleError::MutationService(e.to_string()),
            })?;

        // Best-effort: publish WS disconnect event when new role lacks document:read.
        // Effective permission check: DB override first, then base_role default (steps 7-8).
        let lost_read = self.check_lost_document_read(&new_role).await;
        if lost_read {
            self.workspace_event_publisher
                .publish(domain::WorkspaceEvent::MemberRoleChanged {
                    workspace_id: command.workspace_id,
                    target_user_id: command.target_user_id,
                })
                .await;
        }

        Ok(())
    }

    /// Check if a role effectively lacks document:read permission.
    ///
    /// Effective permission resolution per design doc (workspace.md steps 7-8):
    /// 1. Check workspace_role_permissions table for (role_id, "document:read") override
    /// 2. If override exists, use its `granted` flag
    /// 3. If no override exists, fall back to base_role default permission matrix
    ///
    /// Returns true if document:read is NOT granted (i.e., read access is lost).
    /// Best-effort: on DB errors, assumes read is NOT lost (fail-open for disconnect events).
    async fn check_lost_document_read(
        &self,
        new_role: &domain::workspace::WorkspaceRole,
    ) -> bool {
        let overrides = match self
            .role_perm_repo
            .find_by_role_id(new_role.id)
            .await
        {
            Ok(perms) => perms,
            Err(_) => return false, // Best-effort: fail-open on DB error
        };

        // Check for explicit document:read override
        for perm in &overrides {
            if perm.permission == permission::DOCUMENT_READ {
                return !perm.granted;
            }
        }

        // No override: fall back to base_role default
        !permission::default_grant(new_role.base_role, permission::DOCUMENT_READ)
    }
}
