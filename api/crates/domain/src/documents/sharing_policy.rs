use crate::workspaces::permissions::{
    PERM_DOC_VIEW, PERM_SHARE_CREATE, PERM_SHARE_DELETE, PermissionSet,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingPolicyError {
    Forbidden,
}

pub fn ensure_share_create_allowed(permissions: &PermissionSet) -> Result<(), SharingPolicyError> {
    if permissions.allows(PERM_SHARE_CREATE) {
        Ok(())
    } else {
        Err(SharingPolicyError::Forbidden)
    }
}

pub fn ensure_share_delete_allowed(permissions: &PermissionSet) -> Result<(), SharingPolicyError> {
    if permissions.allows(PERM_SHARE_DELETE) {
        Ok(())
    } else {
        Err(SharingPolicyError::Forbidden)
    }
}

pub fn ensure_document_view_allowed(permissions: &PermissionSet) -> Result<(), SharingPolicyError> {
    if permissions.allows(PERM_DOC_VIEW) {
        Ok(())
    } else {
        Err(SharingPolicyError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::permissions::{PERM_DOC_VIEW, PERM_SHARE_CREATE, PERM_SHARE_DELETE};

    #[test]
    fn share_create_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_share_create_allowed(&perms),
            Err(SharingPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_SHARE_CREATE]);
        assert_eq!(ensure_share_create_allowed(&perms), Ok(()));
    }

    #[test]
    fn share_delete_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_share_delete_allowed(&perms),
            Err(SharingPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_SHARE_DELETE]);
        assert_eq!(ensure_share_delete_allowed(&perms), Ok(()));
    }

    #[test]
    fn document_view_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_document_view_allowed(&perms),
            Err(SharingPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_DOC_VIEW]);
        assert_eq!(ensure_document_view_allowed(&perms), Ok(()));
    }
}
