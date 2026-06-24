use std::io::Write;
use std::path::Component;

use anyhow::anyhow;
use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::documents::comment_markers::strip_comment_markers_from_bytes;
use crate::documents::ports::comment_repository::CommentRepository;
use crate::documents::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::services::realtime::snapshot::SnapshotService;

pub struct SnapshotDownload {
    pub filename: String,
    pub bytes: Vec<u8>,
    pub snapshot: SnapshotArchiveRecord,
}

pub struct DownloadSnapshot<'a, F, S, SNAP, C>
where
    F: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
    SNAP: SnapshotServiceProvider + ?Sized,
    C: CommentRepository + ?Sized,
{
    pub files: &'a F,
    pub storage: &'a S,
    pub snapshots: &'a SNAP,
    pub comments: &'a C,
}

#[async_trait]
pub trait SnapshotServiceProvider {
    async fn load_markdown_with_record(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>>;
}

#[async_trait]
impl SnapshotServiceProvider for SnapshotService {
    async fn load_markdown_with_record(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
        self.load_archive_markdown(snapshot_id).await
    }
}

impl<'a, F, S, SNAP, C> DownloadSnapshot<'a, F, S, SNAP, C>
where
    F: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
    SNAP: SnapshotServiceProvider + ?Sized,
    C: CommentRepository + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<SnapshotDownload>> {
        let Some((snapshot_record, markdown)) = self
            .snapshots
            .load_markdown_with_record(snapshot_id)
            .await?
        else {
            return Ok(None);
        };
        if snapshot_record.document_id != document_id {
            anyhow::bail!("snapshot_document_mismatch");
        }

        let comment_markers = self
            .comments
            .list_threads(workspace_id, document_id)
            .await?
            .into_iter()
            .map(|record| record.thread.marker)
            .collect::<Vec<_>>();
        let markdown_bytes =
            strip_comment_markers_from_bytes(markdown.into_bytes(), &comment_markers);
        let stored_attachments = self
            .files
            .list_storage_paths_for_document(document_id)
            .await?;
        let doc_dir = self.storage.build_doc_file_path(document_id).await?;
        let doc_dir_parent = doc_dir
            .parent()
            .ok_or_else(|| anyhow!("document directory missing"))?
            .to_path_buf();

        let mut attachments: Vec<(String, Vec<u8>)> = Vec::new();
        for stored_path in stored_attachments {
            let full_path = self.storage.absolute_from_relative(&stored_path);
            if !full_path.starts_with(&doc_dir_parent) {
                continue;
            }
            let relative = match full_path.strip_prefix(&doc_dir_parent) {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            if relative.as_os_str().is_empty() {
                continue;
            }
            if relative
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
            {
                continue;
            }
            let rel_str = relative.to_string_lossy().replace('\\', "/");
            let data = self.storage.read_bytes(full_path.as_path()).await?;
            attachments.push((rel_str, data));
        }

        let safe_title = sanitize_filename(&snapshot_record.label);
        let archive_name = format!("{}-snapshot.zip", safe_title);
        let markdown_entry = format!("{}/{}.md", safe_title, safe_title);
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file(markdown_entry, options)?;
            zip.write_all(&markdown_bytes)?;
            for (rel_path, data) in attachments {
                let entry_path = format!("{}/{}", safe_title, rel_path.trim_start_matches('/'));
                zip.start_file(entry_path, options)?;
                zip.write_all(&data)?;
            }
            zip.finish()?;
        }
        let bytes = cursor.into_inner();

        Ok(Some(SnapshotDownload {
            filename: archive_name,
            bytes,
            snapshot: snapshot_record,
        }))
    }
}

fn sanitize_filename(name: &str) -> String {
    let mut s = name.trim().to_string();
    let invalid = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    for ch in invalid {
        s = s.replace(ch, "-");
    }
    s = s.replace(' ', "_");
    if s.is_empty() {
        s = "snapshot".into();
    }
    if s.len() > 100 {
        s.truncate(100);
    }
    s
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use async_trait::async_trait;
    use chrono::Utc;

    use super::*;
    use crate::core::ports::errors::PortResult;
    use crate::core::ports::storage::storage_port::StoredAttachment;
    use crate::documents::ports::comment_repository::{
        CommentReplyRecord, CommentThreadRecord, CommentThreadUpdate, CommentThreadWithReplies,
        NewCommentReply, NewCommentThread,
    };
    use crate::documents::ports::files::files_repository::{
        FileMeta, FilePathMeta, FileRecord, StoredFileScope,
    };

    struct EmptyFiles;

    #[async_trait]
    impl FilesRepository for EmptyFiles {
        async fn is_workspace_document(
            &self,
            _doc_id: Uuid,
            _workspace_id: Uuid,
        ) -> PortResult<bool> {
            Ok(true)
        }

        async fn insert_file(
            &self,
            _doc_id: Uuid,
            _filename: &str,
            _content_type: Option<&str>,
            _size: i64,
            _storage_path: &str,
            _content_hash: &str,
        ) -> PortResult<Uuid> {
            Ok(Uuid::new_v4())
        }

        async fn get_file_meta(&self, _file_id: Uuid) -> PortResult<Option<FileMeta>> {
            Ok(None)
        }

        async fn get_file_path_by_doc_and_name(
            &self,
            _doc_id: Uuid,
            _filename: &str,
        ) -> PortResult<Option<FilePathMeta>> {
            Ok(None)
        }

        async fn list_storage_paths_for_document(&self, _doc_id: Uuid) -> PortResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn list_files_for_document(&self, _doc_id: Uuid) -> PortResult<Vec<FileRecord>> {
            Ok(Vec::new())
        }

        async fn list_storage_paths_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> PortResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn find_by_storage_path(
            &self,
            _storage_path: &str,
        ) -> PortResult<Option<StoredFileScope>> {
            Ok(None)
        }

        async fn update_storage_path(&self, _file_id: Uuid, _storage_path: &str) -> PortResult<()> {
            Ok(())
        }

        async fn update_hash_and_size(
            &self,
            _file_id: Uuid,
            _size: i64,
            _content_hash: &str,
        ) -> PortResult<()> {
            Ok(())
        }

        async fn delete_by_id(&self, _file_id: Uuid) -> PortResult<()> {
            Ok(())
        }
    }

    struct FakeStorage;

    #[async_trait]
    impl StorageResolverPort for FakeStorage {
        async fn build_doc_dir(&self, doc_id: Uuid) -> PortResult<PathBuf> {
            Ok(PathBuf::from(format!("/tmp/{doc_id}")))
        }

        async fn build_doc_file_path(&self, doc_id: Uuid) -> PortResult<PathBuf> {
            Ok(PathBuf::from(format!("/tmp/{doc_id}/document.md")))
        }

        fn relative_from_uploads(&self, abs: &Path) -> String {
            abs.to_string_lossy().into_owned()
        }

        fn user_repo_dir(&self, user_id: Uuid) -> String {
            user_id.to_string()
        }

        fn absolute_from_relative(&self, rel: &str) -> PathBuf {
            PathBuf::from(rel)
        }

        async fn resolve_upload_path(&self, _doc_id: Uuid, rest_path: &str) -> PortResult<PathBuf> {
            Ok(PathBuf::from(rest_path))
        }

        async fn read_bytes(&self, _abs_path: &Path) -> PortResult<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn exists(&self, _abs_path: &Path) -> PortResult<bool> {
            Ok(false)
        }

        async fn write_bytes(&self, _abs_path: &Path, _data: &[u8]) -> PortResult<()> {
            Ok(())
        }

        async fn store_doc_attachment(
            &self,
            _doc_id: Uuid,
            _original_filename: Option<&str>,
            _bytes: &[u8],
        ) -> PortResult<StoredAttachment> {
            Ok(StoredAttachment {
                filename: "file.bin".to_string(),
                relative_path: "file.bin".to_string(),
                size: 0,
                content_hash: String::new(),
            })
        }
    }

    struct FakeSnapshots {
        snapshot_id: Uuid,
        record: SnapshotArchiveRecord,
        markdown: String,
    }

    #[async_trait]
    impl SnapshotServiceProvider for FakeSnapshots {
        async fn load_markdown_with_record(
            &self,
            snapshot_id: Uuid,
        ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
            if snapshot_id == self.snapshot_id {
                Ok(Some((self.record.clone(), self.markdown.clone())))
            } else {
                Ok(None)
            }
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
            unreachable!("not used by snapshot download tests")
        }

        async fn add_reply(
            &self,
            _input: NewCommentReply,
        ) -> PortResult<Option<CommentReplyRecord>> {
            unreachable!("not used by snapshot download tests")
        }

        async fn update_thread(
            &self,
            _input: CommentThreadUpdate,
        ) -> PortResult<Option<CommentThreadWithReplies>> {
            unreachable!("not used by snapshot download tests")
        }
    }

    #[tokio::test]
    async fn snapshot_download_strips_only_persisted_comment_markers() {
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
            snapshot_id,
            record,
            markdown: format!("alpha{marker} beta\n{manual}"),
        };
        let comments = FakeComments {
            workspace_id,
            document_id,
            marker,
        };
        let uc = DownloadSnapshot {
            files: &EmptyFiles,
            storage: &FakeStorage,
            snapshots: &snapshots,
            comments: &comments,
        };

        let download = uc
            .execute(workspace_id, document_id, snapshot_id)
            .await
            .expect("snapshot download succeeds")
            .expect("snapshot exists");
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(download.bytes)).expect("valid snapshot zip");
        let mut entry = archive
            .by_name("Snapshot/Snapshot.md")
            .expect("markdown entry");
        let mut markdown = String::new();
        std::io::Read::read_to_string(&mut entry, &mut markdown).expect("read markdown");

        assert_eq!(markdown, format!("alpha beta\n{manual}"));
    }
}
