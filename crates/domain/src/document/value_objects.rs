//! Document domain value objects

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Document ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentId(Uuid);

impl DocumentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DocumentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tag ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagId(i64);

impl TagId {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for TagId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Document Link ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentLinkId(Uuid);

impl DocumentLinkId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DocumentLinkId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DocumentLinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Snapshot Archive ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotArchiveId(Uuid);

impl SnapshotArchiveId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for SnapshotArchiveId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SnapshotArchiveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

/// Link type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkType(String);

impl LinkType {
    pub fn new(link_type: impl Into<String>) -> Self {
        Self(link_type.into())
    }

    pub fn wikilink() -> Self {
        Self("wikilink".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Snapshot archive kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveKind {
    Manual,
    Auto,
}

impl ArchiveKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArchiveKind::Manual => "manual",
            ArchiveKind::Auto => "auto",
        }
    }
}

impl std::str::FromStr for ArchiveKind {
    type Err = ArchiveKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "manual" => Ok(ArchiveKind::Manual),
            "auto" => Ok(ArchiveKind::Auto),
            _ => Err(ArchiveKindError::InvalidKind(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveKindError {
    #[error("invalid archive kind: {0}")]
    InvalidKind(String),
}
