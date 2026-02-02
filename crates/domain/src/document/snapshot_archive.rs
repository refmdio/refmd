//! DocumentSnapshotArchive entity

use chrono::{DateTime, Utc};

use crate::identity::UserId;
use super::value_objects::{ArchiveKind, DocumentId, SnapshotArchiveId};

/// Document snapshot archive (labeled snapshot)
#[derive(Debug, Clone)]
pub struct DocumentSnapshotArchive {
    pub id: SnapshotArchiveId,
    pub document_id: DocumentId,
    pub snapshot_id: i64,
    pub label: String,
    pub notes: Option<String>,
    pub kind: ArchiveKind,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
}

impl DocumentSnapshotArchive {
    /// Create a new manual snapshot archive
    pub fn manual(
        document_id: DocumentId,
        snapshot_id: i64,
        label: String,
        notes: Option<String>,
        created_by: Option<UserId>,
    ) -> Self {
        Self {
            id: SnapshotArchiveId::new(),
            document_id,
            snapshot_id,
            label,
            notes,
            kind: ArchiveKind::Manual,
            created_by,
            created_at: Utc::now(),
        }
    }

    /// Create a new auto snapshot archive
    pub fn auto(
        document_id: DocumentId,
        snapshot_id: i64,
        label: String,
    ) -> Self {
        Self {
            id: SnapshotArchiveId::new(),
            document_id,
            snapshot_id,
            label,
            notes: None,
            kind: ArchiveKind::Auto,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    /// Check if archive is manual
    pub fn is_manual(&self) -> bool {
        self.kind == ArchiveKind::Manual
    }
}
