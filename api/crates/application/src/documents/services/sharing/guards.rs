use domain::documents::sharing_policy;
use domain::workspaces::permissions::PermissionSet;

use crate::core::services::errors::ServiceError;

pub(super) fn ensure_share_create_permission(
    permissions: &PermissionSet,
) -> Result<(), ServiceError> {
    sharing_policy::ensure_share_create_allowed(permissions).map_err(|_| ServiceError::Forbidden)
}

pub(super) fn ensure_share_delete_permission(
    permissions: &PermissionSet,
) -> Result<(), ServiceError> {
    sharing_policy::ensure_share_delete_allowed(permissions).map_err(|_| ServiceError::Forbidden)
}

pub(super) fn ensure_doc_view_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    sharing_policy::ensure_document_view_allowed(permissions).map_err(|_| ServiceError::Forbidden)
}
