//! Shared workspace permission check utility

use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission,
    WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Error from workspace permission check.
#[derive(Debug, Error)]
pub enum WorkspaceAccessError<MR: std::error::Error, RR: std::error::Error> {
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied")]
    PermissionDenied,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<MR: std::error::Error, RR: std::error::Error> crate::types::AppError for WorkspaceAccessError<MR, RR> {
    fn is_not_found(&self) -> bool {
        matches!(self, Self::NotMember)
    }

    fn is_access_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied)
    }
}

/// Check that a user is a member of a workspace and has the required permission.
///
/// This encapsulates the member→role→permission pattern used across many handlers.
pub async fn check_workspace_permission<MR, RR>(
    member_repo: &Arc<MR>,
    role_repo: &Arc<RR>,
    workspace_id: WorkspaceId,
    user_id: UserId,
    permission: WorkspacePermission,
) -> Result<(), WorkspaceAccessError<MR::Error, RR::Error>>
where
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
{
    let member = member_repo
        .find_by_workspace_and_user(workspace_id, user_id)
        .await
        .map_err(WorkspaceAccessError::MemberRepository)?
        .ok_or(WorkspaceAccessError::NotMember)?;

    let role = role_repo
        .find_by_id(member.role_id)
        .await
        .map_err(WorkspaceAccessError::RoleRepository)?
        .ok_or(WorkspaceAccessError::NotMember)?;

    if !can_perform(role.base_role, permission) {
        return Err(WorkspaceAccessError::PermissionDenied);
    }

    Ok(())
}

/// Error from loading a document with workspace permission check.
#[derive(Debug, Error)]
pub enum LoadDocumentPermissionError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

/// Generate a `from_load` method that converts `LoadDocumentPermissionError` into the target error type.
///
/// The target error must have variants `DocumentNotFound`, `WorkspaceAccess(WorkspaceAccessError<MR, RR>)`,
/// and `DocumentRepository(DR)`.
///
/// # Usage
///
/// ```ignore
/// // 3-generic form: error type has DR, MR, RR
/// crate::util::workspace_access::impl_from_load_doc_perm!(
///     [DR, MR, RR] MyError<DR, MR, RR>
/// );
///
/// // Extra-generic form: error type has additional generics before/after DR, MR, RR
/// crate::util::workspace_access::impl_from_load_doc_perm!(
///     [DKR, DR, MR, RR] MyError<DKR, DR, MR, RR>, DR, MR, RR
/// );
/// ```
macro_rules! impl_from_load_doc_perm {
    // 3-generic form: generics match DR, MR, RR directly
    ([$dr:ident, $mr:ident, $rr:ident] $err_type:ty) => {
        impl<$dr: std::error::Error, $mr: std::error::Error, $rr: std::error::Error> $err_type {
            fn from_load(e: $crate::util::workspace_access::LoadDocumentPermissionError<$dr, $mr, $rr>) -> Self {
                match e {
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentNotFound => Self::DocumentNotFound,
                    $crate::util::workspace_access::LoadDocumentPermissionError::WorkspaceAccess(e) => Self::WorkspaceAccess(e),
                    $crate::util::workspace_access::LoadDocumentPermissionError::DocumentRepository(e) => Self::DocumentRepository(e),
                }
            }
        }
    };
    // N-generic form: specify which generics are DR, MR, RR explicitly
    ([$($gen:ident),+] $err_type:ty, $dr:ident, $mr:ident, $rr:ident) => {
        impl<$($gen: std::error::Error),+> $err_type {
            fn from_load(e: $crate::util::workspace_access::LoadDocumentPermissionError<$dr, $mr, $rr>) -> Self {
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
pub async fn load_document_with_permission<DR, MR, RR>(
    document_repo: &Arc<DR>,
    member_repo: &Arc<MR>,
    role_repo: &Arc<RR>,
    document_id: DocumentId,
    user_id: UserId,
    permission: WorkspacePermission,
) -> Result<Document, LoadDocumentPermissionError<DR::Error, MR::Error, RR::Error>>
where
    DR: DocumentRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
{
    let document = document_repo
        .find_by_id(document_id)
        .await
        .map_err(LoadDocumentPermissionError::DocumentRepository)?
        .ok_or(LoadDocumentPermissionError::DocumentNotFound)?;

    check_workspace_permission(member_repo, role_repo, document.workspace_id, user_id, permission)
        .await
        .map_err(LoadDocumentPermissionError::WorkspaceAccess)?;

    Ok(document)
}
