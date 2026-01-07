use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::core::dtos::TextDiffResult;
use crate::documents::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;

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
    // E2EE fields
    pub nonce: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
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
            nonce: record.nonce,
            signature: record.signature,
        }
    }
}

/// Snapshot detail DTO
/// - For E2EE documents: content is encrypted, nonce is Some
/// - For non-E2EE documents: content is plaintext Yjs state, nonce is None
#[derive(Debug, Clone)]
pub struct SnapshotDetailDto {
    pub id: Uuid,
    /// Yjs snapshot bytes (encrypted for E2EE, plaintext for non-E2EE)
    pub content: Vec<u8>,
    /// Nonce for decryption (present for E2EE documents)
    pub nonce: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Document content DTO (unified for both plaintext and E2EE)
/// - For E2EE: content is encrypted bytes, nonce is present
/// - For plaintext: content is Yjs state bytes, nonce is None
#[derive(Debug, Clone)]
pub struct ContentDto {
    /// Document content as Yjs snapshot bytes (encrypted for E2EE, plaintext for non-E2EE)
    pub content: Vec<u8>,
    /// Nonce for decryption (present for E2EE documents)
    pub nonce: Option<Vec<u8>>,
}
