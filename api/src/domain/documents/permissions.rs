use crate::domain::workspaces::permissions::{
    PermissionSet, PERM_DOC_ARCHIVE, PERM_DOC_CREATE, PERM_DOC_DELETE, PERM_DOC_EDIT,
    PERM_DOC_MOVE, PERM_FOLDER_CREATE, PERM_FOLDER_DELETE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentPermissionError {
    Forbidden,
}

pub type Result<T> = std::result::Result<T, DocumentPermissionError>;

pub fn ensure_can_create(permissions: &PermissionSet, doc_type: &str) -> Result<()> {
    ensure_folder_sensitive_permission(
        permissions,
        doc_type,
        PERM_DOC_CREATE,
        Some(PERM_FOLDER_CREATE),
    )
}

pub fn ensure_can_delete(permissions: &PermissionSet, doc_type: &str) -> Result<()> {
    ensure_folder_sensitive_permission(
        permissions,
        doc_type,
        PERM_DOC_DELETE,
        Some(PERM_FOLDER_DELETE),
    )
}

pub fn ensure_can_edit(permissions: &PermissionSet, doc_type: &str) -> Result<()> {
    ensure_folder_sensitive_permission(permissions, doc_type, PERM_DOC_EDIT, None)
}

pub fn ensure_can_move(permissions: &PermissionSet, doc_type: &str) -> Result<()> {
    ensure_folder_sensitive_permission(permissions, doc_type, PERM_DOC_MOVE, None)
}

pub fn ensure_can_archive(permissions: &PermissionSet, doc_type: &str) -> Result<()> {
    ensure_folder_sensitive_permission(permissions, doc_type, PERM_DOC_ARCHIVE, None)
}

fn ensure_folder_sensitive_permission(
    permissions: &PermissionSet,
    doc_type: &str,
    doc_permission: &'static str,
    folder_permission: Option<&'static str>,
) -> Result<()> {
    let required = if doc_type == "folder" {
        folder_permission.unwrap_or(doc_permission)
    } else {
        doc_permission
    };
    if permissions.allows(required) {
        Ok(())
    } else {
        Err(DocumentPermissionError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_creation_requires_folder_permission() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_CREATE]);
        assert_eq!(
            ensure_can_create(&perms, "folder"),
            Err(DocumentPermissionError::Forbidden)
        );

        let perms = PermissionSet::from_slice(&[PERM_FOLDER_CREATE]);
        assert_eq!(ensure_can_create(&perms, "folder"), Ok(()));
    }

    #[test]
    fn document_creation_requires_doc_permission() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_CREATE]);
        assert_eq!(ensure_can_create(&perms, "document"), Ok(()));
    }

    #[test]
    fn folder_delete_uses_folder_permission_when_available() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_DELETE]);
        assert_eq!(
            ensure_can_delete(&perms, "folder"),
            Err(DocumentPermissionError::Forbidden)
        );

        let perms = PermissionSet::from_slice(&[PERM_FOLDER_DELETE]);
        assert_eq!(ensure_can_delete(&perms, "folder"), Ok(()));
    }

    #[test]
    fn edit_move_archive_use_doc_permissions_for_all_types() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_EDIT, PERM_DOC_MOVE, PERM_DOC_ARCHIVE]);
        assert_eq!(ensure_can_edit(&perms, "folder"), Ok(()));
        assert_eq!(ensure_can_move(&perms, "folder"), Ok(()));
        assert_eq!(ensure_can_archive(&perms, "folder"), Ok(()));
    }
}
