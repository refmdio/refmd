//! Remove member from workspace command
//!
//! Removes a member from a workspace. Requires member:remove permission.
//! Cannot remove the last Owner.
//!
//! Owner continuity: when the target is an Owner, uses MemberMutationService
//! which performs SELECT ... FOR UPDATE to prevent concurrent race conditions.
//!
//! After successful removal, best-effort KEK/DEK rotation marking is triggered
//! per ADR-002 (forward secrecy mitigation) and ADR-003 (immediate DEK rotation).

use crate::encryption::services::mark_rotation::MarkRotationService;
use crate::encryption::services::rotation_marking_service::RotationMarkingService;
use crate::util::workspace_access::{MemberWithRole, WorkspaceAccessError, check_workspace_permission};
use crate::workspace::MemberMutationService;
use crate::workspace_events::WorkspaceEventPublisher;
use domain::document::DocumentRepository;
use domain::encryption::DocumentEncryptedKeyRepository;
use domain::identity::UserId;
use domain::workspace::{
    BaseRole, WorkspaceId, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Remove member command
#[derive(Debug)]
pub struct RemoveMemberCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub target_user_id: UserId,
}

/// Remove member error
#[derive(Debug, Error)]
pub enum RemoveMemberError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("target member not found")]
    TargetNotFound,

    #[error("cannot_modify_owner")]
    CannotRemoveOwner,

    #[error("last_owner")]
    LastOwner,

    #[error("operator_demoted")]
    OperatorDemoted,

    #[error("role_conflict")]
    RoleConflict,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("mutation service error: {0}")]
    MutationService(String),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    RemoveMemberError<MR, RR, RPR>,
    not_found: [
        RemoveMemberError::TargetNotFound,
        RemoveMemberError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        RemoveMemberError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        RemoveMemberError::CannotRemoveOwner,
        RemoveMemberError::OperatorDemoted,
    ],
    conflict: [
        RemoveMemberError::RoleConflict,
    ],
    unprocessable: [
        RemoveMemberError::LastOwner,
    ],
);

/// Remove member handler
pub struct RemoveMemberHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, DocR: ?Sized, DKR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    member_mutation_service: Arc<dyn MemberMutationService>,
    document_repo: Arc<DocR>,
    document_key_repo: Arc<DKR>,
    rotation_marking_service: Arc<dyn RotationMarkingService>,
    workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, DocR: ?Sized, DKR: ?Sized> RemoveMemberHandler<MR, RR, RPR, DocR, DKR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    DocR: DocumentRepository,
    DKR: DocumentEncryptedKeyRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        member_mutation_service: Arc<dyn MemberMutationService>,
        document_repo: Arc<DocR>,
        document_key_repo: Arc<DKR>,
        rotation_marking_service: Arc<dyn RotationMarkingService>,
        workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            member_mutation_service,
            document_repo,
            document_key_repo,
            rotation_marking_service,
            workspace_event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: RemoveMemberCommand,
    ) -> Result<(), RemoveMemberError<MR::Error, RR::Error, RPR::Error>> {
        let is_self_removal = command.user_id == command.target_user_id;

        // 1. Permission check — self-removal only requires membership, not member:remove
        let actor = if is_self_removal {
            let member = self
                .member_repo
                .find_by_workspace_and_user(command.workspace_id, command.user_id)
                .await
                .map_err(RemoveMemberError::MemberRepository)?
                .ok_or(RemoveMemberError::WorkspaceAccess(WorkspaceAccessError::NotMember))?;
            let role = self
                .role_repo
                .find_by_id(member.role_id)
                .await
                .map_err(RemoveMemberError::RoleRepository)?
                .ok_or(RemoveMemberError::WorkspaceAccess(WorkspaceAccessError::NotMember))?;
            MemberWithRole { role }
        } else {
            check_workspace_permission(
                &self.member_repo,
                &self.role_repo,
                &self.role_perm_repo,
                command.workspace_id,
                command.user_id,
                permission::MEMBER_REMOVE,
            )
            .await
            .map_err(RemoveMemberError::WorkspaceAccess)?
        };

        // 2. Load target member
        let target_member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.target_user_id)
            .await
            .map_err(RemoveMemberError::MemberRepository)?
            .ok_or(RemoveMemberError::TargetNotFound)?;

        // 3. Load target's role
        let target_role = self
            .role_repo
            .find_by_id(target_member.role_id)
            .await
            .map_err(RemoveMemberError::RoleRepository)?
            .ok_or(RemoveMemberError::TargetNotFound)?;

        // 4. Owner protection: only Owner can remove Owner
        if target_role.base_role == BaseRole::Owner
            && actor.role.base_role != BaseRole::Owner
        {
            return Err(RemoveMemberError::CannotRemoveOwner);
        }

        // 5. If target is Owner, use atomic service with SELECT FOR UPDATE
        if target_role.base_role == BaseRole::Owner {
            use crate::workspace::MemberMutationError;
            self.member_mutation_service
                .remove_owner_member(
                    command.workspace_id,
                    command.user_id,
                    command.target_user_id,
                )
                .await
                .map_err(|e| match e {
                    MemberMutationError::LastOwner => RemoveMemberError::LastOwner,
                    MemberMutationError::OperatorDemoted => RemoveMemberError::OperatorDemoted,
                    MemberMutationError::TargetNotFound => RemoveMemberError::TargetNotFound,
                    MemberMutationError::TargetRoleNotFound => RemoveMemberError::TargetNotFound,
                    MemberMutationError::RoleConflict => RemoveMemberError::RoleConflict,
                    MemberMutationError::Database(msg) => RemoveMemberError::MutationService(msg),
                })?;

            // Best-effort KEK/DEK rotation after owner removal
            self.mark_rotation_best_effort(command.workspace_id).await;

            // Best-effort: publish event for real-time WS disconnect
            self.workspace_event_publisher
                .publish(domain::WorkspaceEvent::MemberRemoved {
                    workspace_id: command.workspace_id,
                    removed_user_id: command.target_user_id,
                })
                .await;

            return Ok(());
        }

        // 6. Non-owner target: conditional delete with role_id guard for both the
        //    target (concurrent promotion protection) and the operator (concurrent
        //    demotion protection via operator freshness guard).
        use crate::workspace::MemberMutationError;
        self.member_mutation_service
            .remove_non_owner_member(
                command.workspace_id,
                command.target_user_id,
                target_member.role_id,
                command.user_id,
                actor.role.id,
            )
            .await
            .map_err(|e| match e {
                MemberMutationError::RoleConflict => RemoveMemberError::RoleConflict,
                MemberMutationError::OperatorDemoted => RemoveMemberError::OperatorDemoted,
                MemberMutationError::Database(msg) => RemoveMemberError::MutationService(msg),
                _ => RemoveMemberError::MutationService(e.to_string()),
            })?;

        // 7. Best-effort KEK/DEK rotation marking (ADR-002, ADR-003).
        //    The member is already removed; rotation failures are logged but
        //    do not fail the removal. A background job can detect missed markers.
        self.mark_rotation_best_effort(command.workspace_id).await;

        // Best-effort: publish event for real-time WS disconnect
        self.workspace_event_publisher
            .publish(domain::WorkspaceEvent::MemberRemoved {
                workspace_id: command.workspace_id,
                removed_user_id: command.target_user_id,
            })
            .await;

        Ok(())
    }

    /// Best-effort KEK/DEK rotation marking after member removal.
    ///
    /// Per ADR-002 (forward secrecy mitigation) and ADR-003 (immediate DEK rotation),
    /// removing a member triggers rotation to prevent the removed member from
    /// decrypting future content with cached keys.
    ///
    /// **Design decision**: rotation marking is intentionally non-atomic with member
    /// removal. If rotation marking fails, the member is still removed (access revoked)
    /// and a background reconciliation job detects and retries missed markers. Making
    /// this atomic would mean a transient rotation failure blocks member removal,
    /// which is a worse UX and security trade-off (the removed member retains access).
    async fn mark_rotation_best_effort(&self, workspace_id: WorkspaceId) {
        let rotation_service = MarkRotationService::new(
            self.member_repo.clone(),
            self.document_repo.clone(),
            self.document_key_repo.clone(),
            self.rotation_marking_service.clone(),
        );

        match rotation_service.mark_for_workspace(workspace_id).await {
            Ok(result) => {
                if let Some(ref failures) = result.rotation_marking_failures {
                    tracing::warn!(
                        workspace_id = %workspace_id,
                        failed_workspaces = ?failures.failed_workspace_ids,
                        failed_documents = ?failures.failed_document_ids,
                        "partial rotation marking failures after member removal"
                    );
                } else {
                    tracing::info!(
                        workspace_id = %workspace_id,
                        revoked_invitations = result.revoked_invitation_count,
                        "KEK/DEK rotation marked after member removal"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    workspace_id = %workspace_id,
                    error = %e,
                    "failed to mark KEK/DEK rotation after member removal"
                );
            }
        }
    }
}
