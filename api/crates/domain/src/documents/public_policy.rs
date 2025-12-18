use crate::workspaces::permissions::{PERM_PUBLIC_PUBLISH, PERM_PUBLIC_UNPUBLISH, PermissionSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicPolicyError {
    Forbidden,
}

pub fn ensure_public_publish_allowed(permissions: &PermissionSet) -> Result<(), PublicPolicyError> {
    if permissions.allows(PERM_PUBLIC_PUBLISH) {
        Ok(())
    } else {
        Err(PublicPolicyError::Forbidden)
    }
}

pub fn ensure_public_unpublish_allowed(
    permissions: &PermissionSet,
) -> Result<(), PublicPolicyError> {
    if permissions.allows(PERM_PUBLIC_UNPUBLISH) {
        Ok(())
    } else {
        Err(PublicPolicyError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::permissions::{PERM_PUBLIC_PUBLISH, PERM_PUBLIC_UNPUBLISH};

    #[test]
    fn publish_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_public_publish_allowed(&perms),
            Err(PublicPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_PUBLIC_PUBLISH]);
        assert_eq!(ensure_public_publish_allowed(&perms), Ok(()));
    }

    #[test]
    fn unpublish_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_public_unpublish_allowed(&perms),
            Err(PublicPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_PUBLIC_UNPUBLISH]);
        assert_eq!(ensure_public_unpublish_allowed(&perms), Ok(()));
    }
}
