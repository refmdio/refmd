use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::application::dto::diff::TextDiffResult;
use crate::application::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;

#[derive(Debug, Clone, Copy, Default)]
pub enum DocumentListFilter {
    #[default]
    Active,
    Archived,
    All,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum SnapshotDiffBaseMode {
    #[default]
    Auto,
    ForceCurrent,
    ForcePrevious,
}

#[derive(Debug, Clone)]
pub struct SnapshotSummaryDto {
    pub id: Uuid,
    pub document_id: Uuid,
    pub label: String,
    pub notes: Option<String>,
    pub kind: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub byte_size: i64,
    pub content_hash: String,
}

#[derive(Debug, Clone)]
pub enum SnapshotDiffSideDto {
    Current {
        markdown: String,
    },
    Snapshot {
        snapshot: SnapshotSummaryDto,
        markdown: String,
    },
}

#[derive(Debug, Clone)]
pub struct SnapshotDiffDto {
    pub base: SnapshotDiffSideDto,
    pub target: SnapshotDiffSideDto,
    pub diff: TextDiffResult,
}

impl From<SnapshotArchiveRecord> for SnapshotSummaryDto {
    fn from(record: SnapshotArchiveRecord) -> Self {
        Self {
            id: record.id,
            document_id: record.document_id,
            label: record.label,
            notes: record.notes,
            kind: record.kind,
            created_at: record.created_at,
            created_by: record.created_by,
            byte_size: record.byte_size,
            content_hash: record.content_hash,
        }
    }
}
