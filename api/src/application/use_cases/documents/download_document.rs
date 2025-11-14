use std::path::Component;

use uuid::Uuid;

use crate::application::access::{self, Actor, Capability};
use crate::application::dto::document_export::{DocumentDownload, DocumentDownloadFormat};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::document_exporter::{
    DocumentExportAssets, DocumentExportAttachment, DocumentExporter,
};
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StoragePort;
use crate::application::services::realtime::snapshot::SnapshotService;

pub struct DownloadDocument<'a, D, F, S, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
    A: AccessRepository + ?Sized,
    SH: ShareAccessPort + ?Sized,
{
    pub documents: &'a D,
    pub files: &'a F,
    pub storage: &'a S,
    pub access: &'a A,
    pub shares: &'a SH,
    pub snapshot: &'a SnapshotService,
    pub exporter: &'a dyn DocumentExporter,
}

impl<'a, D, F, S, A, SH> DownloadDocument<'a, D, F, S, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
    A: AccessRepository + ?Sized,
    SH: ShareAccessPort + ?Sized,
{
    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        format: DocumentDownloadFormat,
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

        let export = match self.snapshot.export_current_markdown(&doc_id).await? {
            Some(export) => export,
            None => return Ok(None),
        };
        let markdown_bytes = export.bytes;
        let doc_dir = self.storage.build_doc_dir(doc_id).await?;

        let stored_attachments = self.files.list_storage_paths_for_document(doc_id).await?;
        let mut attachments: Vec<DocumentExportAttachment> = Vec::new();
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
            attachments.push(DocumentExportAttachment {
                relative_path: rel_str,
                bytes: data,
            });
        }

        let safe_title = sanitize_filename(&document.title);
        let display_title = document.title.trim();
        let display_title = if display_title.is_empty() {
            None
        } else {
            Some(display_title.to_string())
        };

        let export_assets = DocumentExportAssets {
            safe_title,
            display_title,
            markdown: markdown_bytes,
            attachments,
        };

        let download = self.exporter.export(export_assets, format).await?;
        Ok(Some(download))
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
