use uuid::Uuid;

use crate::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::services::realtime::snapshot::SnapshotService;

pub struct ListSnapshots<'a> {
    pub snapshots: &'a SnapshotService,
}

impl<'a> ListSnapshots<'a> {
    pub async fn execute(
        &self,
        document_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<SnapshotArchiveRecord>> {
        self.snapshots
            .list_archives(document_id, limit, offset)
            .await
    }
}
