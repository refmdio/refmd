//! Document infrastructure implementations

pub mod archive_repository;
pub mod document_repository;
pub mod link_repository;
pub mod snapshot_repository;
pub mod tag_repository;
pub mod update_repository;

pub use archive_repository::{PgSnapshotArchiveRepository, PgSnapshotArchiveRepositoryError};
pub use document_repository::{PgDocumentRepository, PgDocumentRepositoryError};
pub use link_repository::{PgDocumentLinkRepository, PgDocumentLinkRepositoryError};
pub use snapshot_repository::{PgDocumentSnapshotRepository, PgDocumentSnapshotRepositoryError};
pub use tag_repository::{
    PgDocumentTagRepository, PgDocumentTagRepositoryError, PgTagRepository, PgTagRepositoryError,
};
pub use update_repository::{PgDocumentUpdateRepository, PgDocumentUpdateRepositoryError};
