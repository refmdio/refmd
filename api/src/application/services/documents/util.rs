use tracing::error;

use crate::application::dto::documents::DocumentListFilter;
use crate::application::ports::document_repository::DocumentListState;
use crate::application::services::errors::ServiceError;
use crate::domain::documents::hierarchy;
use crate::domain::documents::policy::DocumentPolicyError;

pub(super) fn to_repo_state(filter: DocumentListFilter) -> DocumentListState {
    match filter {
        DocumentListFilter::Active => DocumentListState::Active,
        DocumentListFilter::Archived => DocumentListState::Archived,
        DocumentListFilter::All => DocumentListState::All,
    }
}

pub(super) fn map_policy_error(err: DocumentPolicyError) -> ServiceError {
    match err {
        DocumentPolicyError::Forbidden => ServiceError::Forbidden,
        DocumentPolicyError::Archived | DocumentPolicyError::NotArchived => ServiceError::Conflict,
        DocumentPolicyError::FolderNotSupported => {
            ServiceError::BadRequest("operation_not_supported_for_folder")
        }
    }
}

pub(super) fn map_parent_error(err: hierarchy::ParentValidationError) -> ServiceError {
    match err {
        hierarchy::ParentValidationError::NotFound => ServiceError::NotFound,
        hierarchy::ParentValidationError::Archived => ServiceError::Conflict,
    }
}

pub(super) fn map_sqlx_error(err: sqlx::Error) -> ServiceError {
    error!(error = ?err, "document_sql_error");
    ServiceError::Unexpected(err.into())
}

