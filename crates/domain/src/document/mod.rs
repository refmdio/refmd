//! Document domain
//!
//! Manages documents and updates.

#[allow(clippy::module_inception)]
pub mod document;
pub mod document_update;
pub mod repository;
pub mod value_objects;

// Re-export commonly used types
pub use document::Document;
pub use document_update::{DocumentUpdate, NewDocumentUpdateParams};
pub use repository::{DocumentRepository, DocumentUpdateRepository};
pub use value_objects::{DocumentId, DocumentType, DocumentTypeError};
