//! Document domain
//!
//! Manages documents, updates, and collaboration snapshots.

#[allow(clippy::module_inception)]
pub mod document;
pub mod document_snapshot;
pub mod document_update;
pub mod repository;
pub mod value_objects;

// Re-export commonly used types
pub use document::Document;
pub use document_snapshot::{DocumentSnapshot, NewDocumentSnapshotParams, SnapshotProof};
pub use document_update::{DocumentUpdate, NewDocumentUpdateParams};
pub use repository::{DocumentRepository, DocumentSnapshotRepository, DocumentUpdateRepository, SnapshotSaveOutcome};
pub use value_objects::{DocumentId, DocumentSnapshotId, DocumentType, DocumentTypeError, PublicData};
