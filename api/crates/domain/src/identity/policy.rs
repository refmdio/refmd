use crate::workspaces::permissions::{PERM_API_TOKEN_MANAGE, PERM_SHORTCUT_UPDATE, PermissionSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPolicyError {
    Forbidden,
}

pub fn ensure_api_token_manage_allowed(
    permissions: &PermissionSet,
) -> Result<(), IdentityPolicyError> {
    if permissions.allows(PERM_API_TOKEN_MANAGE) {
        Ok(())
    } else {
        Err(IdentityPolicyError::Forbidden)
    }
}

pub fn ensure_shortcut_update_allowed(
    permissions: &PermissionSet,
) -> Result<(), IdentityPolicyError> {
    if permissions.allows(PERM_SHORTCUT_UPDATE) {
        Ok(())
    } else {
        Err(IdentityPolicyError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::permissions::{PERM_API_TOKEN_MANAGE, PERM_SHORTCUT_UPDATE};

    #[test]
    fn api_token_manage_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_api_token_manage_allowed(&perms),
            Err(IdentityPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_API_TOKEN_MANAGE]);
        assert_eq!(ensure_api_token_manage_allowed(&perms), Ok(()));
    }

    #[test]
    fn shortcut_update_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_shortcut_update_allowed(&perms),
            Err(IdentityPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_SHORTCUT_UPDATE]);
        assert_eq!(ensure_shortcut_update_allowed(&perms), Ok(()));
    }
}
