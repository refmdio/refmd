//! Shared workspace permission check utility

use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRole,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    default_grant, is_at_or_above, ceiling,
};
use std::sync::Arc;
use thiserror::Error;

/// Member + Role pair returned from permission checks.
pub struct MemberWithRole {
    pub role: WorkspaceRole,
}

/// Error from workspace permission check.
#[derive(Debug, Error)]
pub enum WorkspaceAccessError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error>
{
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied")]
    PermissionDenied,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role permission repository error: {0}")]
    RolePermissionRepository(RPR),
}

impl<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> crate::types::AppError
    for WorkspaceAccessError<MR, RR, RPR>
{
    fn is_not_found(&self) -> bool {
        matches!(self, Self::NotMember)
    }

    fn is_access_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied)
    }
}

/// Membership-only error (simpler than WorkspaceAccessError, no RBAC repos needed).
#[derive(Debug, Error)]
pub enum MembershipError<MR: std::error::Error> {
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("member repository error: {0}")]
    MemberRepository(MR),
}

impl<MR: std::error::Error> crate::types::AppError for MembershipError<MR> {
    fn is_not_found(&self) -> bool {
        matches!(self, Self::NotMember)
    }
}

/// Check that a user is a member of a workspace (no RBAC permission check).
///
/// Used for KEK/encryption endpoints where the design specifies
/// "PoP + membership" without RBAC.
pub async fn check_workspace_membership<MR>(
    member_repo: &Arc<MR>,
    workspace_id: WorkspaceId,
    user_id: UserId,
) -> Result<(), MembershipError<MR::Error>>
where
    MR: WorkspaceMemberRepository + ?Sized,
{
    member_repo
        .find_by_workspace_and_user(workspace_id, user_id)
        .await
        .map_err(MembershipError::MemberRepository)?
        .ok_or(MembershipError::NotMember)?;
    Ok(())
}

/// Check that a user is a member of a workspace and has the required permission.
///
/// Implements the design doc's 8-step permission check algorithm:
/// 1. Validate permission key (reject unknown perms immediately, no DB lookup)
/// 2. (Workspace resolution — handled by callers)
/// 3. Load member
/// 4. Load role
/// 5. Owner fast-path (Owner always has all known permissions)
/// 6. Ceiling check (role.base_role must be at or above permission ceiling)
/// 7. Load DB overrides; if override exists, use it
/// 8. Otherwise, use default_grant matrix
pub async fn check_workspace_permission<MR, RR, RPR>(
    member_repo: &Arc<MR>,
    role_repo: &Arc<RR>,
    role_perm_repo: &Arc<RPR>,
    workspace_id: WorkspaceId,
    user_id: UserId,
    perm: &str,
) -> Result<MemberWithRole, WorkspaceAccessError<MR::Error, RR::Error, RPR::Error>>
where
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
    RPR: WorkspaceRolePermissionRepository + ?Sized,
{
    // 1. Validate permission key (fail-closed: unknown perms rejected before any DB lookup)
    if !domain::workspace::permission::is_valid_permission(perm) {
        return Err(WorkspaceAccessError::PermissionDenied);
    }

    // 3. Load member
    let member = member_repo
        .find_by_workspace_and_user(workspace_id, user_id)
        .await
        .map_err(WorkspaceAccessError::MemberRepository)?
        .ok_or(WorkspaceAccessError::NotMember)?;

    // 4. Load role
    let role = role_repo
        .find_by_id(member.role_id)
        .await
        .map_err(WorkspaceAccessError::RoleRepository)?
        .ok_or(WorkspaceAccessError::NotMember)?;

    // 5. Owner fast-path: Owner always has all known permissions
    if role.base_role == domain::workspace::BaseRole::Owner {
        return Ok(MemberWithRole { role });
    }

    // 6. Ceiling check: role.base_role must be privileged enough
    if let Some(ceil) = ceiling(perm) {
        if !is_at_or_above(role.base_role, ceil) {
            return Err(WorkspaceAccessError::PermissionDenied);
        }
    } else {
        // Unknown permission — deny (should not reach here due to step 1, but defensive)
        return Err(WorkspaceAccessError::PermissionDenied);
    }

    // 7. Load DB overrides for this role
    let overrides = role_perm_repo
        .find_by_role_id(role.id)
        .await
        .map_err(WorkspaceAccessError::RolePermissionRepository)?;

    // 7b. Check DB override
    if let Some(ovr) = overrides.iter().find(|o| o.permission == perm) {
        if ovr.granted {
            return Ok(MemberWithRole { role });
        } else {
            return Err(WorkspaceAccessError::PermissionDenied);
        }
    }

    // 8. Default grant matrix fallback
    if default_grant(role.base_role, perm) {
        Ok(MemberWithRole { role })
    } else {
        Err(WorkspaceAccessError::PermissionDenied)
    }
}

/// Error from loading a document with workspace permission check.
#[derive(Debug, Error)]
pub enum LoadDocumentPermissionError<
    DR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

/// Generate a `from_load` method that converts `LoadDocumentPermissionError` into the target error type.
///
/// The target error must have variants `DocumentNotFound`, `WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>)`,
/// and `DocumentRepository(DR)`.
///
/// # Usage
///
/// ```ignore
/// // 4-generic form: error type has DR, MR, RR, RPR
/// crate::util::workspace_access::impl_from_load_doc_perm!(
///     [DR, MR, RR, RPR] MyError<DR, MR, RR, RPR>
/// );
///
/// // Extra-generic form: error type has additional generics before/after DR, MR, RR, RPR
/// crate::util::workspace_access::impl_from_load_doc_perm!(
///     [DKR, DR, MR, RR, RPR] MyError<DKR, DR, MR, RR, RPR>, DR, MR, RR, RPR
/// );
/// ```
macro_rules! impl_from_load_doc_perm {
    // 4-generic form: generics match DR, MR, RR, RPR directly
    ([$dr:ident, $mr:ident, $rr:ident, $rpr:ident] $err_type:ty) => {
        impl<$dr: std::error::Error, $mr: std::error::Error, $rr: std::error::Error, $rpr: std::error::Error> $err_type {
            fn from_load(e: $crate::util::workspace_access::LoadDocumentPermissionError<$dr, $mr, $rr, $rpr>) -> Self {
                match e {
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentNotFound => Self::DocumentNotFound,
                    $crate::util::workspace_access::LoadDocumentPermissionError::WorkspaceAccess(e) => Self::WorkspaceAccess(e),
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentRepository(e) => Self::DocumentRepository(e),
                }
            }
        }
    };
    // N-generic form: specify which generics are DR, MR, RR, RPR explicitly
    ([$($gen:ident),+] $err_type:ty, $dr:ident, $mr:ident, $rr:ident, $rpr:ident) => {
        impl<$($gen: std::error::Error),+> $err_type {
            fn from_load(e: $crate::util::workspace_access::LoadDocumentPermissionError<$dr, $mr, $rr, $rpr>) -> Self {
                match e {
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentNotFound => Self::DocumentNotFound,
                    $crate::util::workspace_access::LoadDocumentPermissionError::WorkspaceAccess(e) => Self::WorkspaceAccess(e),
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentRepository(e) => Self::DocumentRepository(e),
                }
            }
        }
    };
}

pub(crate) use impl_from_load_doc_perm;

/// Load a document by ID and verify the user has the required workspace permission.
///
/// Combines the two-step pattern (document lookup + permission check) used by most
/// document-related handlers into a single call.
pub async fn load_document_with_permission<DR, MR, RR, RPR>(
    document_repo: &Arc<DR>,
    member_repo: &Arc<MR>,
    role_repo: &Arc<RR>,
    role_perm_repo: &Arc<RPR>,
    document_id: DocumentId,
    user_id: UserId,
    permission: &str,
) -> Result<Document, LoadDocumentPermissionError<DR::Error, MR::Error, RR::Error, RPR::Error>>
where
    DR: DocumentRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
    RPR: WorkspaceRolePermissionRepository + ?Sized,
{
    let document = document_repo
        .find_by_id(document_id)
        .await
        .map_err(LoadDocumentPermissionError::DocumentRepository)?
        .ok_or(LoadDocumentPermissionError::DocumentNotFound)?;

    check_workspace_permission(
        member_repo,
        role_repo,
        role_perm_repo,
        document.workspace_id,
        user_id,
        permission,
    )
    .await
    .map_err(LoadDocumentPermissionError::WorkspaceAccess)?;

    Ok(document)
}
