use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::path::{Component, Path};

use chrono::Utc;
use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::access::{self, Actor, Capability};
use crate::documents::dtos::{DocumentDownload, DocumentDownloadFormat};
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::document_exporter::{
    DocumentExportAssets, DocumentExportAttachment, DocumentExporter,
};
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use crate::documents::services::realtime::snapshot::SnapshotService;
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use thiserror::Error;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

pub struct DownloadDocument<'a, D, F, S, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
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
    S: StorageResolverPort + ?Sized,
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
        let capability = access::resolve_document(self.access, self.shares, actor, doc_id).await?;
        if capability < Capability::View {
            return Ok(None);
        }

        let document = match self.documents.get_by_id(doc_id).await? {
            Some(doc) => doc,
            None => return Ok(None),
        };

        if document.doc_type == DocumentType::Folder {
            return self.download_folder(actor, &document, format).await;
        }

        let export_assets = match self.prepare_document_assets(&document).await? {
            Some(assets) => assets,
            None => return Ok(None),
        };

        let download = self.exporter.export(export_assets, format).await?;
        Ok(Some(download))
    }

    async fn prepare_document_assets(
        &self,
        document: &DomainDocument,
    ) -> anyhow::Result<Option<DocumentExportAssets>> {
        if document.doc_type == DocumentType::Folder {
            return Ok(None);
        }
        let export = match self.snapshot.export_current_markdown(&document.id).await? {
            Some(export) => export,
            None => return Ok(None),
        };
        let doc_dir = self.storage.build_doc_dir(document.id).await?;
        let attachments = self.collect_attachments(document.id, &doc_dir).await?;
        let safe_title = sanitize_filename(document.title.as_str());
        let display_title = document.title.as_str().trim();
        let display_title = if display_title.is_empty() {
            None
        } else {
            Some(display_title.to_string())
        };
        Ok(Some(DocumentExportAssets {
            safe_title,
            display_title,
            markdown: export.bytes,
            attachments,
        }))
    }

    async fn collect_attachments(
        &self,
        doc_id: Uuid,
        doc_dir: &Path,
    ) -> anyhow::Result<Vec<DocumentExportAttachment>> {
        let stored_attachments = self.files.list_storage_paths_for_document(doc_id).await?;
        let mut attachments: Vec<DocumentExportAttachment> = Vec::new();
        for stored_path in stored_attachments {
            let full_path = self.storage.absolute_from_relative(&stored_path);
            if !full_path.starts_with(doc_dir) {
                continue;
            }
            let relative = match full_path.strip_prefix(doc_dir) {
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
        Ok(attachments)
    }

    async fn download_folder(
        &self,
        actor: &Actor,
        folder: &DomainDocument,
        format: DocumentDownloadFormat,
    ) -> anyhow::Result<Option<DocumentDownload>> {
        if format != DocumentDownloadFormat::Archive {
            return Err(FolderDownloadUnsupportedFormat.into());
        }

        let mut nodes: HashMap<Uuid, DomainDocument> = HashMap::new();
        nodes.insert(folder.id, folder.clone());
        let subtree = self
            .documents
            .list_owned_subtree_documents(folder.workspace_id, folder.id)
            .await?;
        for entry in subtree {
            if entry.id == folder.id {
                continue;
            }
            if let Some(doc) = self.documents.get_by_id(entry.id).await? {
                nodes.insert(doc.id, doc);
            }
        }

        let root_name = sanitize_filename(folder.title.as_str());
        let entries = self
            .build_archive_entries(actor, &nodes, folder.id, Some(folder.desired_path.as_str()))
            .await?;
        let bytes = build_folder_archive(&root_name, &entries)?;
        Ok(Some(DocumentDownload {
            filename: format.file_name(&root_name),
            content_type: format.content_type().to_string(),
            bytes,
        }))
    }

    pub async fn download_workspace_root(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        workspace_name: &str,
        format: DocumentDownloadFormat,
    ) -> anyhow::Result<Option<DocumentDownload>> {
        if format != DocumentDownloadFormat::Archive {
            return Err(FolderDownloadUnsupportedFormat.into());
        }

        let documents = self
            .documents
            .list_workspace_documents(workspace_id)
            .await?;
        let mut nodes: HashMap<Uuid, DomainDocument> = HashMap::new();
        for doc in documents {
            nodes.insert(doc.id, doc);
        }

        let root = DomainDocument {
            id: workspace_id,
            owner_id: workspace_id,
            owner_user_id: None,
            workspace_id,
            title: domain::documents::title::Title::new(workspace_name),
            parent_id: None,
            doc_type: DocumentType::Folder,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by_plugin: None,
            slug: domain::documents::path::Slug::new(sanitize_filename(workspace_name))
                .unwrap_or_else(|_| domain::documents::path::Slug::from_title(workspace_name)),
            desired_path: domain::documents::path::DesiredPath::root(),
            path: None,
            created_by: None,
            archived_at: None,
            archived_by: None,
            archived_parent_id: None,
        };
        nodes.insert(root.id, root);

        let root_name = sanitize_filename(workspace_name);
        let entries = self
            .build_archive_entries(actor, &nodes, workspace_id, None)
            .await?;
        let bytes = build_folder_archive(&root_name, &entries)?;
        Ok(Some(DocumentDownload {
            filename: format.file_name(&root_name),
            content_type: format.content_type().to_string(),
            bytes,
        }))
    }

    async fn build_archive_entries(
        &self,
        actor: &Actor,
        nodes: &HashMap<Uuid, DomainDocument>,
        root_id: Uuid,
        base_prefix: Option<&str>,
    ) -> anyhow::Result<Vec<FolderDownloadEntry>> {
        let mut entries: Vec<FolderDownloadEntry> = Vec::new();
        for doc in nodes.values() {
            if doc.id == root_id || doc.doc_type == DocumentType::Folder {
                continue;
            }
            let capability =
                access::resolve_document(self.access, self.shares, actor, doc.id).await?;
            if capability < Capability::View {
                continue;
            }
            let Some(assets) = self.prepare_document_assets(doc).await? else {
                continue;
            };
            let relative_path = resolve_relative_path(doc, base_prefix);
            entries.push(FolderDownloadEntry {
                relative_path,
                assets,
            });
        }
        entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(entries)
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

fn resolve_relative_path(doc: &DomainDocument, base_prefix: Option<&str>) -> String {
    let path = doc.desired_path.as_str().trim_start_matches('/');
    if let Some(base) = base_prefix {
        let base = base.trim_start_matches('/');
        if !base.is_empty() {
            if let Some(stripped) = path.strip_prefix(base) {
                let trimmed = stripped.trim_start_matches('/');
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    if path.is_empty() {
        format!("{}.md", sanitize_filename(doc.title.as_str()))
    } else {
        path.to_string()
    }
}

struct FolderDownloadEntry {
    relative_path: String,
    assets: DocumentExportAssets,
}

fn build_folder_archive(
    root_name: &str,
    entries: &[FolderDownloadEntry],
) -> anyhow::Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        zip.add_directory(format!("{root_name}/"), options)?;
        for entry in entries {
            let markdown_entry = format!("{}/{}", root_name, entry.relative_path);
            zip.start_file(markdown_entry, options)?;
            zip.write_all(&entry.assets.markdown)?;
            let doc_parent = Path::new(&entry.relative_path)
                .parent()
                .map(|p| p.to_string_lossy().trim_start_matches('/').to_string())
                .unwrap_or_default();
            for attachment in &entry.assets.attachments {
                let rel_path = attachment.relative_path.trim_start_matches('/');
                let attachment_entry = if doc_parent.is_empty() {
                    format!("{}/{}", root_name, rel_path)
                } else {
                    format!("{}/{}/{}", root_name, doc_parent, rel_path)
                };
                zip.start_file(attachment_entry, options)?;
                zip.write_all(&attachment.bytes)?;
            }
        }
        zip.finish()?;
    }
    Ok(cursor.into_inner())
}

#[derive(Debug, Error)]
#[error("folder downloads only support archive format")]
pub struct FolderDownloadUnsupportedFormat;
