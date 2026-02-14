//! Document infrastructure implementations

pub mod document_repository;
pub mod update_repository;

pub use document_repository::{PgDocumentRepository, PgDocumentRepositoryError};
pub use update_repository::{PgDocumentUpdateRepository, PgDocumentUpdateRepositoryError};
