//! Shared document validation utilities
//!
//! Common validation logic used by create_document and update_document commands.

use domain::document::{DocumentId, DocumentRepository};
use domain::workspace::WorkspaceId;
use thiserror::Error;

/// Validate that encrypted_title and encrypted_title_nonce are both provided or both omitted.
///
/// Returns `true` if the fields are consistent, `false` otherwise.
pub fn encrypted_title_fields_valid(
    title: &Option<Vec<u8>>,
    nonce: &Option<Vec<u8>>,
) -> bool {
    matches!((title, nonce), (Some(_), Some(_)) | (None, None))
}

/// Error from parent document validation.
#[derive(Debug, Error)]
pub enum ParentValidationError<DR: std::error::Error> {
    #[error("parent document not found")]
    NotFound,
    #[error("parent is not a folder")]
    NotFolder,
    #[error("parent document is archived")]
    Archived,
    #[error("parent and child are in different workspaces")]
    WorkspaceMismatch,
    #[error("document repository error: {0}")]
    Repository(DR),
}

/// Validate that a parent document exists, is a folder, is not archived,
/// and belongs to the same workspace.
pub async fn validate_parent_document<DR: DocumentRepository + ?Sized>(
    repo: &DR,
    parent_id: DocumentId,
    workspace_id: WorkspaceId,
) -> Result<(), ParentValidationError<DR::Error>> {
    let parent = repo
        .find_by_id(parent_id)
        .await
        .map_err(ParentValidationError::Repository)?
        .ok_or(ParentValidationError::NotFound)?;

    if !parent.is_folder() {
        return Err(ParentValidationError::NotFolder);
    }
    if parent.is_archived() {
        return Err(ParentValidationError::Archived);
    }
    if parent.workspace_id != workspace_id {
        return Err(ParentValidationError::WorkspaceMismatch);
    }

    Ok(())
}

/// Generate a `from_parent_validation` method that converts `ParentValidationError<DR>` into
/// the target error type.
///
/// The target error must have variants `ParentNotFound`, `ParentNotFolder`, `ParentArchived`,
/// and `DocumentRepository(DR)`.
///
/// # Usage
///
/// ```ignore
/// crate::util::document_validation::impl_from_parent_validation!(
///     [DR, MR, RR] MyError<DR, MR, RR>
/// );
/// ```
macro_rules! impl_from_parent_validation {
    ([$($gen:ident),+] $err_type:ty) => {
        impl<$($gen: std::error::Error),+> $err_type {
            fn from_parent_validation(e: $crate::util::document_validation::ParentValidationError<DR>) -> Self {
                match e {
                    $crate::util::document_validation::ParentValidationError::NotFound
                    | $crate::util::document_validation::ParentValidationError::WorkspaceMismatch => {
                        Self::ParentNotFound
                    }
                    $crate::util::document_validation::ParentValidationError::NotFolder => Self::ParentNotFolder,
                    $crate::util::document_validation::ParentValidationError::Archived => Self::ParentArchived,
                    $crate::util::document_validation::ParentValidationError::Repository(e) => Self::DocumentRepository(e),
                }
            }
        }
    };
}

pub(crate) use impl_from_parent_validation;
