//! Document infrastructure implementations

pub mod document_repository;
pub mod snapshot_repository;
pub mod update_repository;

pub use document_repository::{PgDocumentRepository, PgDocumentRepositoryError};
pub use snapshot_repository::{PgSnapshotRepository, PgSnapshotRepositoryError};
pub use update_repository::{PgDocumentUpdateRepository, PgDocumentUpdateRepositoryError};
