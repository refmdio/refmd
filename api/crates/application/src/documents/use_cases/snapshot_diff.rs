use async_trait::async_trait;
use uuid::Uuid;

use crate::core::dtos::TextDiffResult;
use crate::core::services::diff::text_diff::compute_text_diff;
use crate::documents::comment_markers::strip_comment_markers;
use crate::documents::dtos::SnapshotDiffBaseMode;
use crate::documents::ports::comment_repository::CommentRepository;
use crate::documents::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::services::realtime::snapshot::SnapshotService;

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

pub struct SnapshotDiff<'a, RT, SNAP, C>
where
    RT: RealtimeEngine + ?Sized,
    SNAP: SnapshotDiffSource + ?Sized,
    C: CommentRepository + ?Sized,
{
    pub snapshots: &'a SNAP,
    pub realtime: &'a RT,
    pub comments: &'a C,
}

#[async_trait]
pub trait SnapshotDiffSource {
    async fn load_markdown_with_record(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>>;

    async fn load_previous_markdown(
        &self,
        document_id: Uuid,
        before_version: i64,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>>;
}

#[async_trait]
impl SnapshotDiffSource for SnapshotService {
    async fn load_markdown_with_record(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
        self.load_archive_markdown(snapshot_id).await
    }

    async fn load_previous_markdown(
        &self,
        document_id: Uuid,
        before_version: i64,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
        self.load_previous_archive_markdown(document_id, before_version)
            .await
    }
}

impl<'a, RT, SNAP, C> SnapshotDiff<'a, RT, SNAP, C>
where
    RT: RealtimeEngine + ?Sized,
    SNAP: SnapshotDiffSource + ?Sized,
    C: CommentRepository + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        snapshot_id: Uuid,
        compare_to: Option<Uuid>,
        base_mode: SnapshotDiffBaseMode,
    ) -> anyhow::Result<Option<SnapshotDiffResult>> {
        let Some((target_record, target_markdown)) = self
            .snapshots
            .load_markdown_with_record(snapshot_id)
            .await?
        else {
            return Ok(None);
        };

        if target_record.document_id != document_id {
            anyhow::bail!("snapshot_document_mismatch");
        }
        let comment_markers = self.load_comment_markers(workspace_id, document_id).await?;
        let target_markdown = strip_comment_markers(&target_markdown, &comment_markers);

        let selected_snapshot = SnapshotDiffTarget::Snapshot {
            record: target_record.clone(),
            markdown: target_markdown.clone(),
        };

        let (base, target) = if let Some(compare_id) = compare_to {
            let Some((base_record, base_markdown)) =
                self.snapshots.load_markdown_with_record(compare_id).await?
            else {
                return Ok(None);
            };
            if base_record.document_id != document_id {
                anyhow::bail!("compare_snapshot_document_mismatch");
            }
            let base_markdown = strip_comment_markers(&base_markdown, &comment_markers);
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
                        markdown: self
                            .load_current_markdown(document_id, &comment_markers)
                            .await?,
                    },
                ),
                SnapshotDiffBaseMode::ForcePrevious | SnapshotDiffBaseMode::Auto => {
                    if let Some((prev_record, prev_markdown)) = self
                        .snapshots
                        .load_previous_markdown(document_id, target_record.version)
                        .await?
                    {
                        (
                            SnapshotDiffBase::Snapshot {
                                record: prev_record,
                                markdown: strip_comment_markers(&prev_markdown, &comment_markers),
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
                                markdown: self
                                    .load_current_markdown(document_id, &comment_markers)
                                    .await?,
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

    async fn load_current_markdown(
        &self,
        document_id: Uuid,
        comment_markers: &[String],
    ) -> anyhow::Result<String> {
        let current = self
            .realtime
            .get_content(&document_id.to_string())
            .await?
            .unwrap_or_default();
        Ok(strip_comment_markers(&current, comment_markers))
    }

    async fn load_comment_markers(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<String>> {
        Ok(self
            .comments
            .list_threads(workspace_id, document_id)
            .await?
            .into_iter()
            .map(|record| record.thread.marker)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::Utc;

    use super::*;
    use crate::core::ports::errors::PortResult;
    use crate::documents::ports::comment_repository::{
        CommentReplyRecord, CommentThreadRecord, CommentThreadUpdate, CommentThreadWithReplies,
        NewCommentReply, NewCommentThread,
    };
    use crate::documents::ports::realtime::realtime_types::{DynRealtimeSink, DynRealtimeStream};

    struct FakeSnapshots {
        target_id: Uuid,
        target: SnapshotArchiveRecord,
        target_markdown: String,
    }

    #[async_trait]
    impl SnapshotDiffSource for FakeSnapshots {
        async fn load_markdown_with_record(
            &self,
            snapshot_id: Uuid,
        ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
            if snapshot_id == self.target_id {
                Ok(Some((self.target.clone(), self.target_markdown.clone())))
            } else {
                Ok(None)
            }
        }

        async fn load_previous_markdown(
            &self,
            _document_id: Uuid,
            _before_version: i64,
        ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
            Ok(None)
        }
    }

    struct FakeRealtime {
        document_id: Uuid,
        content: String,
    }

    #[async_trait]
    impl RealtimeEngine for FakeRealtime {
        async fn subscribe(
            &self,
            _doc_id: &str,
            _sink: DynRealtimeSink,
            _stream: DynRealtimeStream,
            _can_edit: bool,
        ) -> PortResult<()> {
            Ok(())
        }

        async fn get_content(&self, doc_id: &str) -> PortResult<Option<String>> {
            if doc_id == self.document_id.to_string() {
                Ok(Some(self.content.clone()))
            } else {
                Ok(None)
            }
        }

        async fn force_persist(&self, _doc_id: &str) -> PortResult<()> {
            Ok(())
        }

        async fn apply_snapshot(&self, _doc_id: &str, _snapshot: &[u8]) -> PortResult<()> {
            Ok(())
        }
    }

    struct FakeComments {
        workspace_id: Uuid,
        document_id: Uuid,
        marker: String,
    }

    #[async_trait]
    impl CommentRepository for FakeComments {
        async fn list_threads(
            &self,
            workspace_id: Uuid,
            document_id: Uuid,
        ) -> PortResult<Vec<CommentThreadWithReplies>> {
            if workspace_id != self.workspace_id || document_id != self.document_id {
                return Ok(Vec::new());
            }
            Ok(vec![CommentThreadWithReplies {
                thread: CommentThreadRecord {
                    id: Uuid::new_v4(),
                    document_id,
                    marker: self.marker.clone(),
                    quote: "target".to_string(),
                    start_line_number: None,
                    start_column: None,
                    end_line_number: None,
                    end_column: None,
                    start_offset: None,
                    end_offset: None,
                    anchored: true,
                    tags: Vec::new(),
                    created_by: None,
                    created_by_name: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    resolved_at: None,
                    resolved_by: None,
                },
                replies: Vec::new(),
            }])
        }

        async fn create_thread(
            &self,
            _input: NewCommentThread,
        ) -> PortResult<CommentThreadWithReplies> {
            unreachable!("not used by snapshot diff tests")
        }

        async fn add_reply(
            &self,
            _input: NewCommentReply,
        ) -> PortResult<Option<CommentReplyRecord>> {
            unreachable!("not used by snapshot diff tests")
        }

        async fn update_thread(
            &self,
            _input: CommentThreadUpdate,
        ) -> PortResult<Option<CommentThreadWithReplies>> {
            unreachable!("not used by snapshot diff tests")
        }
    }

    #[tokio::test]
    async fn snapshot_diff_strips_persisted_comment_markers_from_displayed_sides() {
        let workspace_id = Uuid::new_v4();
        let document_id = Uuid::new_v4();
        let snapshot_id = Uuid::new_v4();
        let marker = "<!--comment:owned-->".to_string();
        let manual = "<!--comment:manual-->";
        let record = SnapshotArchiveRecord {
            id: snapshot_id,
            document_id,
            version: 1,
            label: "Snapshot".to_string(),
            notes: None,
            kind: "manual".to_string(),
            created_at: Utc::now(),
            created_by: None,
            byte_size: 0,
            content_hash: String::new(),
        };
        let snapshots = FakeSnapshots {
            target_id: snapshot_id,
            target: record,
            target_markdown: format!("old{marker}\n{manual}"),
        };
        let realtime = FakeRealtime {
            document_id,
            content: format!("new{marker}\n{manual}"),
        };
        let comments = FakeComments {
            workspace_id,
            document_id,
            marker,
        };
        let uc = SnapshotDiff {
            snapshots: &snapshots,
            realtime: &realtime,
            comments: &comments,
        };

        let result = uc
            .execute(
                workspace_id,
                document_id,
                snapshot_id,
                None,
                SnapshotDiffBaseMode::ForceCurrent,
            )
            .await
            .expect("snapshot diff succeeds")
            .expect("snapshot exists");

        let expected_old = format!("old\n{manual}");
        let expected_new = format!("new\n{manual}");
        assert_eq!(
            result.diff.old_content.as_deref(),
            Some(expected_old.as_str())
        );
        assert_eq!(
            result.diff.new_content.as_deref(),
            Some(expected_new.as_str())
        );
        assert!(
            result
                .diff
                .diff_lines
                .iter()
                .all(|line| !line.content.contains("<!--comment:owned-->"))
        );
    }
}
