use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SnapshotArchiveInsert<'a> {
    pub document_id: &'a Uuid,
    pub version: i64,
    pub snapshot: &'a [u8],
    pub label: &'a str,
    pub notes: Option<&'a str>,
    pub kind: &'a str,
    pub created_by: Option<&'a Uuid>,
    pub byte_size: i64,
    pub content_hash: &'a str,
}

#[derive(Debug, Clone)]
pub struct SnapshotArchiveRecord {
    pub id: Uuid,
    pub document_id: Uuid,
    pub version: i64,
    pub label: String,
    pub notes: Option<String>,
    pub kind: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub byte_size: i64,
    pub content_hash: String,
}

#[async_trait]
pub trait DocumentSnapshotArchiveRepository: Send + Sync {
    async fn insert(
        &self,
        input: SnapshotArchiveInsert<'_>,
    ) -> anyhow::Result<SnapshotArchiveRecord>;

    async fn get_by_id(&self, id: Uuid)
    -> anyhow::Result<Option<(SnapshotArchiveRecord, Vec<u8>)>>;

    async fn list_for_document(
        &self,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<SnapshotArchiveRecord>>;

    async fn latest_before(
        &self,
        doc_id: Uuid,
        version: i64,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, Vec<u8>)>>;
}
