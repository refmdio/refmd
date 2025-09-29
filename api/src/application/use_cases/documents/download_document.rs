use std::io::Write;
use std::path::{Component, PathBuf};

use uuid::Uuid;

use crate::application::access::{self, Actor, Capability};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::realtime_port::RealtimePort;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StoragePort;

pub struct DocumentDownload {
    pub filename: String,
    pub bytes: Vec<u8>,
}

pub struct DownloadDocument<'a, D, F, S, RT, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
    RT: RealtimePort + ?Sized,
    A: AccessRepository + ?Sized,
    SH: ShareAccessPort + ?Sized,
{
    pub documents: &'a D,
    pub files: &'a F,
    pub storage: &'a S,
    pub realtime: &'a RT,
    pub access: &'a A,
    pub shares: &'a SH,
}

impl<'a, D, F, S, RT, A, SH> DownloadDocument<'a, D, F, S, RT, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
    RT: RealtimePort + ?Sized,
    A: AccessRepository + ?Sized,
    SH: ShareAccessPort + ?Sized,
{
    pub async fn execute(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<DocumentDownload>> {
        let capability = access::resolve_document(self.access, self.shares, actor, doc_id).await;
        if capability < Capability::View {
            return Ok(None);
        }

        let document = match self.documents.get_by_id(doc_id).await? {
            Some(doc) => doc,
            None => return Ok(None),
        };

        if document.doc_type == "folder" {
            return Ok(None);
        }

        self.realtime.force_save_to_fs(&doc_id.to_string()).await?;

        let markdown_path = self.storage.build_doc_file_path(doc_id).await?;
        let doc_dir = markdown_path
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("document directory missing"))?;
        let markdown_bytes = self.storage.read_bytes(markdown_path.as_path()).await?;

        let stored_attachments = self.files.list_storage_paths_for_document(doc_id).await?;
        let mut attachments: Vec<(String, Vec<u8>)> = Vec::new();
        for stored_path in stored_attachments {
            let full_path = self.storage.absolute_from_relative(&stored_path);
            if !full_path.starts_with(&doc_dir) {
                continue;
            }
            let relative = match full_path.strip_prefix(&doc_dir) {
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

        let safe_title = sanitize_filename(&document.title);
        let archive_name = format!("{}.zip", safe_title);
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

        Ok(Some(DocumentDownload {
            filename: archive_name,
            bytes,
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
        s = "document".into();
    }
    if s.len() > 100 {
        s.truncate(100);
    }
    s
}
