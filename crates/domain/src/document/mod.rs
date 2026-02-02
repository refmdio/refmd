//! Document domain
//!
//! Manages documents, updates, snapshots, tags, and links.

pub mod document;
pub mod document_link;
pub mod document_snapshot;
pub mod document_update;
pub mod repository;
pub mod snapshot_archive;
pub mod tag;
pub mod value_objects;

// Re-export commonly used types
pub use document::Document;
pub use document_link::DocumentLink;
pub use document_snapshot::DocumentSnapshot;
pub use document_update::DocumentUpdate;
pub use repository::{
    DocumentLinkRepository, DocumentRepository, DocumentSnapshotRepository,
    DocumentTagRepository, DocumentUpdateRepository, SnapshotArchiveRepository, TagRepository,
};
pub use snapshot_archive::DocumentSnapshotArchive;
pub use tag::{DocumentTag, Tag};
pub use value_objects::{
    ArchiveKind, ArchiveKindError, DocumentId, DocumentLinkId, DocumentType, DocumentTypeError,
    LinkType, SnapshotArchiveId, TagId,
};
