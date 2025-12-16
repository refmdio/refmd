use uuid::Uuid;

use crate::contracts::diff::TextDiffResult;
use crate::contracts::documents::SnapshotDiffBaseMode;
use crate::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::ports::realtime_port::RealtimeEngine;
use crate::services::diff::text_diff::compute_text_diff;
use crate::services::realtime::snapshot::SnapshotService;

pub enum SnapshotDiffSide {
    Current {
        markdown: String,
    },
    Snapshot {
        record: SnapshotArchiveRecord,
        markdown: String,
    },
}

pub type SnapshotDiffBase = SnapshotDiffSide;
pub type SnapshotDiffTarget = SnapshotDiffSide;

pub struct SnapshotDiffResult {
    pub base: SnapshotDiffBase,
    pub target: SnapshotDiffTarget,
    pub diff: TextDiffResult,
}

pub struct SnapshotDiff<'a, RT>
where
    RT: RealtimeEngine + ?Sized,
{
    pub snapshots: &'a SnapshotService,
    pub realtime: &'a RT,
}

impl<'a, RT> SnapshotDiff<'a, RT>
where
    RT: RealtimeEngine + ?Sized,
{
    pub async fn execute(
        &self,
        document_id: Uuid,
        snapshot_id: Uuid,
        compare_to: Option<Uuid>,
        base_mode: SnapshotDiffBaseMode,
    ) -> anyhow::Result<Option<SnapshotDiffResult>> {
        let Some((target_record, target_markdown)) =
            self.snapshots.load_archive_markdown(snapshot_id).await?
        else {
            return Ok(None);
        };

        if target_record.document_id != document_id {
            anyhow::bail!("snapshot_document_mismatch");
        }

        let selected_snapshot = SnapshotDiffTarget::Snapshot {
            record: target_record.clone(),
            markdown: target_markdown.clone(),
        };

        let (base, target) = if let Some(compare_id) = compare_to {
            let Some((base_record, base_markdown)) =
                self.snapshots.load_archive_markdown(compare_id).await?
            else {
                return Ok(None);
            };
            if base_record.document_id != document_id {
                anyhow::bail!("compare_snapshot_document_mismatch");
            }
            (
                SnapshotDiffBase::Snapshot {
                    record: base_record,
                    markdown: base_markdown,
                },
                selected_snapshot,
            )
        } else {
            match base_mode {
                SnapshotDiffBaseMode::ForceCurrent => (
                    SnapshotDiffBase::Snapshot {
                        record: target_record.clone(),
                        markdown: target_markdown.clone(),
                    },
                    SnapshotDiffTarget::Current {
                        markdown: self.load_current_markdown(document_id).await?,
                    },
                ),
                SnapshotDiffBaseMode::ForcePrevious | SnapshotDiffBaseMode::Auto => {
                    if let Some((prev_record, prev_markdown)) = self
                        .snapshots
                        .load_previous_archive_markdown(document_id, target_record.version)
                        .await?
                    {
                        (
                            SnapshotDiffBase::Snapshot {
                                record: prev_record,
                                markdown: prev_markdown,
                            },
                            selected_snapshot,
                        )
                    } else {
                        (
                            SnapshotDiffBase::Snapshot {
                                record: target_record.clone(),
                                markdown: target_markdown.clone(),
                            },
                            SnapshotDiffTarget::Current {
                                markdown: self.load_current_markdown(document_id).await?,
                            },
                        )
                    }
                }
            }
        };

        let base_markdown = match &base {
            SnapshotDiffSide::Current { markdown } => markdown.as_str(),
            SnapshotDiffSide::Snapshot { markdown, .. } => markdown.as_str(),
        };
        let target_markdown = match &target {
            SnapshotDiffSide::Current { markdown } => markdown.as_str(),
            SnapshotDiffSide::Snapshot { markdown, .. } => markdown.as_str(),
        };
        let diff = compute_text_diff(base_markdown, target_markdown, "snapshot.md");

        Ok(Some(SnapshotDiffResult { diff, base, target }))
    }

    async fn load_current_markdown(&self, document_id: Uuid) -> anyhow::Result<String> {
        let current = self
            .realtime
            .get_content(&document_id.to_string())
            .await?
            .unwrap_or_default();
        Ok(current)
    }
}
