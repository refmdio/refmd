//! Document domain value objects

use serde::{Deserialize, Serialize};

/// Opaque public metadata associated with snapshots and updates (secsync protocol).
/// Stored alongside encrypted content; not interpreted by the domain layer.
pub type PublicData = serde_json::Value;

define_id!(/// Document ID
pub DocumentId);

define_id!(/// Collaboration snapshot ID
pub DocumentSnapshotId);

/// Document type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentType {
    Document,
    Folder,
}

impl DocumentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocumentType::Document => "document",
            DocumentType::Folder => "folder",
        }
    }
}

impl std::str::FromStr for DocumentType {
    type Err = DocumentTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "document" => Ok(DocumentType::Document),
            "folder" => Ok(DocumentType::Folder),
            _ => Err(DocumentTypeError::InvalidType(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DocumentTypeError {
    #[error("invalid document type: {0}")]
    InvalidType(String),
}

