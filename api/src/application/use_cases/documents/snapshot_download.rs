use std::io::Write;
use std::path::Component;

use anyhow::anyhow;
use async_trait::async_trait;
use uuid::Uuid;

use crate::application::ports::document_snapshot_archive_repository::SnapshotArchiveRecord;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::services::realtime::snapshot::SnapshotService;

pub struct SnapshotDownload {
    pub filename: String,
    pub bytes: Vec<u8>,
    pub snapshot: SnapshotArchiveRecord,
}

pub struct DownloadSnapshot<'a, F, S, SNAP>
where
    F: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
    SNAP: SnapshotServiceProvider + ?Sized,
{
    pub files: &'a F,
    pub storage: &'a S,
    pub snapshots: &'a SNAP,
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

impl<'a, F, S, SNAP> DownloadSnapshot<'a, F, S, SNAP>
where
    F: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
    SNAP: SnapshotServiceProvider + ?Sized,
{
    pub async fn execute(
        &self,
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

        let markdown_bytes = markdown.into_bytes();
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
