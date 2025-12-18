use std::collections::HashSet;

use uuid::Uuid;

use crate::workspaces::permissions::{PermissionSet, PERM_DOC_CREATE, PERM_DOC_EDIT};

pub const PLUGIN_PERMISSION_DOC_WRITE: &str = "doc.write";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginPolicyError {
    PermissionDenied { permission: String },
}

pub fn ensure_plugin_permission(
    permissions: &HashSet<String>,
    required: &str,
) -> Result<(), PluginPolicyError> {
    if permissions.iter().any(|p| p == required) {
        Ok(())
    } else {
        Err(PluginPolicyError::PermissionDenied {
            permission: required.to_string(),
        })
    }
}

pub fn ensure_workspace_can_create_documents(
    permissions: &PermissionSet,
) -> Result<(), PluginPolicyError> {
    if permissions.allows(PERM_DOC_CREATE) {
        Ok(())
    } else {
        Err(PluginPolicyError::PermissionDenied {
            permission: PERM_DOC_CREATE.to_string(),
        })
    }
}

pub fn ensure_workspace_can_edit_documents(
    permissions: &PermissionSet,
) -> Result<(), PluginPolicyError> {
    if permissions.allows(PERM_DOC_EDIT) {
        Ok(())
    } else {
        Err(PluginPolicyError::PermissionDenied {
            permission: PERM_DOC_EDIT.to_string(),
        })
    }
}

pub fn ensure_doc_id_within_allowed_scope(
    doc_id: Uuid,
    allowed_doc_id: Uuid,
) -> Result<(), PluginPolicyError> {
    if doc_id == allowed_doc_id {
        Ok(())
    } else {
        Err(PluginPolicyError::PermissionDenied {
            permission: PERM_DOC_EDIT.to_string(),
        })
    }
}

pub fn ensure_record_owned_by_plugin(
    record_plugin: &str,
    plugin: &str,
) -> Result<(), PluginPolicyError> {
    if record_plugin == plugin {
        Ok(())
    } else {
        Err(PluginPolicyError::PermissionDenied {
            permission: PERM_DOC_EDIT.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::permissions::{PERM_DOC_CREATE, PERM_DOC_EDIT};

    #[test]
    fn plugin_permission_requires_membership() {
        let perms: HashSet<String> = HashSet::new();
        assert_eq!(
            ensure_plugin_permission(&perms, PLUGIN_PERMISSION_DOC_WRITE),
            Err(PluginPolicyError::PermissionDenied {
                permission: PLUGIN_PERMISSION_DOC_WRITE.to_string()
            })
        );
        let perms: HashSet<String> = [PLUGIN_PERMISSION_DOC_WRITE.to_string()]
            .into_iter()
            .collect();
        assert_eq!(
            ensure_plugin_permission(&perms, PLUGIN_PERMISSION_DOC_WRITE),
            Ok(())
        );
    }

    #[test]
    fn workspace_create_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_workspace_can_create_documents(&perms),
            Err(PluginPolicyError::PermissionDenied {
                permission: PERM_DOC_CREATE.to_string()
            })
        );
        let perms = PermissionSet::from_slice(&[PERM_DOC_CREATE]);
        assert_eq!(ensure_workspace_can_create_documents(&perms), Ok(()));
    }

    #[test]
    fn workspace_edit_requires_permission() {
        let perms = PermissionSet::default();
        assert_eq!(
            ensure_workspace_can_edit_documents(&perms),
            Err(PluginPolicyError::PermissionDenied {
                permission: PERM_DOC_EDIT.to_string()
            })
        );
        let perms = PermissionSet::from_slice(&[PERM_DOC_EDIT]);
        assert_eq!(ensure_workspace_can_edit_documents(&perms), Ok(()));
    }

    #[test]
    fn doc_scope_must_match_allowed_doc_id() {
        let allowed = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert_eq!(
            ensure_doc_id_within_allowed_scope(other, allowed),
            Err(PluginPolicyError::PermissionDenied {
                permission: PERM_DOC_EDIT.to_string()
            })
        );
        assert_eq!(ensure_doc_id_within_allowed_scope(allowed, allowed), Ok(()));
    }

    #[test]
    fn record_owner_must_match_plugin() {
        assert_eq!(ensure_record_owned_by_plugin("a", "a"), Ok(()));
        assert_eq!(
            ensure_record_owned_by_plugin("a", "b"),
            Err(PluginPolicyError::PermissionDenied {
                permission: PERM_DOC_EDIT.to_string()
            })
        );
    }
}

