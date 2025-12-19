use crate::access::permissions::{PERM_GIT_SYNC, PermissionSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPolicyError {
    Forbidden,
}

pub fn ensure_git_sync_allowed(permissions: &PermissionSet) -> Result<(), GitPolicyError> {
    if permissions.allows(PERM_GIT_SYNC) {
        Ok(())
    } else {
        Err(GitPolicyError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::permissions::PERM_GIT_SYNC;

    #[test]
    fn git_sync_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_git_sync_allowed(&perms),
            Err(GitPolicyError::Forbidden)
        );
        let perms = PermissionSet::from_slice(&[PERM_GIT_SYNC]);
        assert_eq!(ensure_git_sync_allowed(&perms), Ok(()));
    }
}
