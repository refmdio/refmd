use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const DOC_TYPE_FOLDER: &str = "folder";
pub const DOC_TYPE_DOCUMENT: &str = "document";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentType {
    Folder,
    Document,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDocumentType;

impl fmt::Display for InvalidDocumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid document type")
    }
}

impl std::error::Error for InvalidDocumentType {}

impl DocumentType {
    pub fn parse(doc_type: &str) -> Option<Self> {
        match doc_type.trim() {
            DOC_TYPE_FOLDER => Some(Self::Folder),
            DOC_TYPE_DOCUMENT => Some(Self::Document),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Folder => DOC_TYPE_FOLDER,
            Self::Document => DOC_TYPE_DOCUMENT,
        }
    }

    pub const fn is_folder(self) -> bool {
        matches!(self, Self::Folder)
    }
}

impl TryFrom<&str> for DocumentType {
    type Error = InvalidDocumentType;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for DocumentType {
    type Err = InvalidDocumentType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidDocumentType)
    }
}

impl fmt::Display for DocumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        assert_eq!(DocumentType::parse("folder"), Some(DocumentType::Folder));
        assert_eq!(
            DocumentType::parse(" document "),
            Some(DocumentType::Document)
        );
        assert_eq!(DocumentType::parse("nope"), None);
        assert_eq!(DocumentType::Folder.as_str(), DOC_TYPE_FOLDER);
        assert_eq!(DocumentType::Document.to_string(), DOC_TYPE_DOCUMENT);
        assert!(DocumentType::Folder.is_folder());
        assert!(!DocumentType::Document.is_folder());
    }
}
