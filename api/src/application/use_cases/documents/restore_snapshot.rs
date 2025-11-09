use chrono::Utc;
use uuid::Uuid;

use crate::application::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::services::realtime::snapshot::{
    SnapshotArchiveKind, SnapshotArchiveOptions, SnapshotPersistOptions, SnapshotService,
    encode_doc_snapshot,
};

pub struct RestoreSnapshot<'a, RT>
where
    RT: RealtimeEngine + ?Sized,
{
    pub snapshots: &'a SnapshotService,
    pub realtime: &'a RT,
}

impl<'a, RT> RestoreSnapshot<'a, RT>
where
    RT: RealtimeEngine + ?Sized,
{
    pub async fn execute(
        &self,
        document_id: Uuid,
        snapshot_id: Uuid,
        actor: Option<Uuid>,
    ) -> anyhow::Result<Option<SnapshotArchiveRecord>> {
        let Some((snapshot_record, snapshot_doc)) =
            self.snapshots.load_archive_doc(snapshot_id).await?
        else {
            return Ok(None);
        };
        if snapshot_record.document_id != document_id {
            anyhow::bail!("snapshot_document_mismatch");
        }

        let snapshot_bytes = encode_doc_snapshot(&snapshot_doc);
        self.realtime
            .apply_snapshot(&document_id.to_string(), snapshot_bytes.as_slice())
            .await?;

        let persist_result = self
            .snapshots
            .persist_snapshot(
                &document_id,
                &snapshot_doc,
                SnapshotPersistOptions {
                    clear_updates: true,
                    ..Default::default()
                },
            )
            .await?;

        let _ = self
            .snapshots
            .write_markdown(&document_id, &snapshot_doc)
            .await?;

        let label = format!(
            "Restore {}, {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            snapshot_record.label
        );
        let archive = self
            .snapshots
            .archive_snapshot(
                &document_id,
                &persist_result.snapshot_bytes,
                persist_result.version,
                SnapshotArchiveOptions {
                    label: label.as_str(),
                    notes: Some("Restored snapshot"),
                    kind: SnapshotArchiveKind::Restore,
                    created_by: actor.as_ref(),
                },
            )
            .await?;
        Ok(Some(archive))
    }
}
