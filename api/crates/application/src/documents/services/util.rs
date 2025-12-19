use crate::core::services::errors::ServiceError;
use crate::documents::dtos::DocumentListFilter;
use crate::documents::ports::document_repository::DocumentListState;
use crate::documents::ports::document_repository::DocumentRepositoryError;
use domain::documents::hierarchy;
use domain::documents::policy::DocumentPolicyError;

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

pub(super) fn map_tx_error(err: anyhow::Error) -> ServiceError {
    match err.downcast::<ServiceError>() {
        Ok(service_error) => service_error,
        Err(err) => match err.downcast::<DocumentRepositoryError>() {
            Ok(repo_err) => ServiceError::from(repo_err),
            Err(err) => ServiceError::from(err),
        },
    }
}
