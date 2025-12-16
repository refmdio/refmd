use chrono::{DateTime, Utc};

use crate::documents::permissions;
use crate::workspaces::permissions::PermissionSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentPolicyError {
    Forbidden,
    Archived,
    NotArchived,
    FolderNotSupported,
}

#[derive(Debug, Clone, Copy)]
pub struct DocumentState<'a> {
    pub doc_type: &'a str,
    pub archived: bool,
}

impl<'a> DocumentState<'a> {
    pub fn new(doc_type: &'a str, archived_at: Option<DateTime<Utc>>) -> Self {
        Self {
            doc_type,
            archived: archived_at.is_some(),
        }
    }
}

pub fn ensure_duplicate_allowed(state: DocumentState) -> Result<(), DocumentPolicyError> {
    if state.doc_type == "folder" {
        return Err(DocumentPolicyError::FolderNotSupported);
    }
    Ok(())
}

pub fn ensure_editable(
    state: DocumentState<'_>,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    ensure_active(state)?;
    permissions::ensure_can_edit(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_movable(
    state: DocumentState<'_>,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    ensure_active(state)?;
    permissions::ensure_can_move(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_archivable(
    state: DocumentState<'_>,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    if state.archived {
        return Err(DocumentPolicyError::Archived);
    }
    permissions::ensure_can_archive(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_unarchivable(
    state: DocumentState<'_>,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    if !state.archived {
        return Err(DocumentPolicyError::NotArchived);
    }
    permissions::ensure_can_archive(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_active(state: DocumentState<'_>) -> Result<(), DocumentPolicyError> {
    if state.archived {
        Err(DocumentPolicyError::Archived)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::permissions::PERM_DOC_EDIT;

    #[test]
    fn duplicate_folder_is_not_allowed() {
        let state = DocumentState::new("folder", None);
        assert_eq!(
            ensure_duplicate_allowed(state),
            Err(DocumentPolicyError::FolderNotSupported)
        );
        let state = DocumentState::new("document", None);
        assert_eq!(ensure_duplicate_allowed(state), Ok(()));
    }

    #[test]
    fn editable_requires_active_and_perm() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_EDIT]);
        let active = DocumentState::new("document", None);
        assert_eq!(ensure_editable(active, &perms), Ok(()));

        let archived = DocumentState::new("document", Some(Utc::now()));
        assert_eq!(
            ensure_editable(archived, &perms),
            Err(DocumentPolicyError::Archived)
        );

        let missing_perm = PermissionSet::default();
        assert_eq!(
            ensure_editable(active, &missing_perm),
            Err(DocumentPolicyError::Forbidden)
        );
    }
}
