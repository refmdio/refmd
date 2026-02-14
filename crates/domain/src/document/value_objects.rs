//! Document domain value objects

use serde::{Deserialize, Serialize};

define_id!(/// Document ID
pub DocumentId);

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

