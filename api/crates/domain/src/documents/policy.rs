use chrono::{DateTime, Utc};

use crate::documents::doc_type::DocumentType;
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
pub struct DocumentState {
    pub doc_type: DocumentType,
    pub archived: bool,
}

impl DocumentState {
    pub fn new(doc_type: DocumentType, archived_at: Option<DateTime<Utc>>) -> Self {
        Self {
            doc_type,
            archived: archived_at.is_some(),
        }
    }
}

pub fn ensure_duplicate_allowed(state: DocumentState) -> Result<(), DocumentPolicyError> {
    if state.doc_type.is_folder() {
        return Err(DocumentPolicyError::FolderNotSupported);
    }
    Ok(())
}

pub fn ensure_editable(
    state: DocumentState,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    ensure_active(state)?;
    permissions::ensure_can_edit(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_movable(
    state: DocumentState,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    ensure_active(state)?;
    permissions::ensure_can_move(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_archivable(
    state: DocumentState,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    if state.archived {
        return Err(DocumentPolicyError::Archived);
    }
    permissions::ensure_can_archive(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_unarchivable(
    state: DocumentState,
    permissions: &PermissionSet,
) -> Result<(), DocumentPolicyError> {
    if !state.archived {
        return Err(DocumentPolicyError::NotArchived);
    }
    permissions::ensure_can_archive(permissions, state.doc_type)
        .map_err(|_| DocumentPolicyError::Forbidden)
}

pub fn ensure_active(state: DocumentState) -> Result<(), DocumentPolicyError> {
    if state.archived {
        Err(DocumentPolicyError::Archived)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::doc_type::DocumentType;
    use crate::workspaces::permissions::{PERM_DOC_ARCHIVE, PERM_DOC_EDIT, PERM_DOC_MOVE};

    #[test]
    fn duplicate_folder_is_not_allowed() {
        let state = DocumentState::new(DocumentType::Folder, None);
        assert_eq!(
            ensure_duplicate_allowed(state),
            Err(DocumentPolicyError::FolderNotSupported)
        );
        let state = DocumentState::new(DocumentType::Document, None);
        assert_eq!(ensure_duplicate_allowed(state), Ok(()));
    }

    #[test]
    fn editable_requires_active_and_perm() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_EDIT]);
        let active = DocumentState::new(DocumentType::Document, None);
        assert_eq!(ensure_editable(active, &perms), Ok(()));

        let archived = DocumentState::new(DocumentType::Document, Some(Utc::now()));
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

    #[test]
    fn movable_requires_active_and_perm() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_MOVE]);
        let active = DocumentState::new(DocumentType::Document, None);
        assert_eq!(ensure_movable(active, &perms), Ok(()));

        let archived = DocumentState::new(DocumentType::Document, Some(Utc::now()));
        assert_eq!(
            ensure_movable(archived, &perms),
            Err(DocumentPolicyError::Archived)
        );

        let missing_perm = PermissionSet::default();
        assert_eq!(
            ensure_movable(active, &missing_perm),
            Err(DocumentPolicyError::Forbidden)
        );
    }

    #[test]
    fn archivable_and_unarchivable_are_guarded_by_state_and_perm() {
        let perms = PermissionSet::from_slice(&[PERM_DOC_ARCHIVE]);
        let active = DocumentState::new(DocumentType::Document, None);
        let archived = DocumentState::new(DocumentType::Document, Some(Utc::now()));

        assert_eq!(ensure_archivable(active, &perms), Ok(()));
        assert_eq!(
            ensure_archivable(archived, &perms),
            Err(DocumentPolicyError::Archived)
        );

        assert_eq!(
            ensure_unarchivable(active, &perms),
            Err(DocumentPolicyError::NotArchived)
        );
        assert_eq!(ensure_unarchivable(archived, &perms), Ok(()));

        let missing_perm = PermissionSet::default();
        assert_eq!(
            ensure_archivable(active, &missing_perm),
            Err(DocumentPolicyError::Forbidden)
        );
        assert_eq!(
            ensure_unarchivable(archived, &missing_perm),
            Err(DocumentPolicyError::Forbidden)
        );
    }

    #[test]
    fn ensure_active_rejects_archived() {
        let active = DocumentState::new(DocumentType::Document, None);
        assert_eq!(ensure_active(active), Ok(()));
        let archived = DocumentState::new(DocumentType::Document, Some(Utc::now()));
        assert_eq!(ensure_active(archived), Err(DocumentPolicyError::Archived));
    }
}
