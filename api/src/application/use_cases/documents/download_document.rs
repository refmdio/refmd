use std::io::Write;
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

use crate::application::access::{self, Actor, Capability};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StoragePort;
use anyhow::Context;
use once_cell::sync::Lazy;
use pandoc::{self, InputFormat, InputKind, OutputFormat, OutputKind, PandocOption, PandocOutput};
use std::sync::Mutex;
use tempfile::tempdir;
use tokio::fs;
use tokio::task;

static PANDOC_WORKDIR_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const DEFAULT_PDF_CSS: &str = r#"
body {
    font-family: 'Noto Sans CJK JP', 'Noto Sans CJK SC', 'Noto Sans CJK TC', 'Noto Sans CJK KR',
                 'Noto Sans JP', 'Noto Sans', 'Noto Serif CJK JP', 'Noto Serif CJK SC',
                 'Noto Serif CJK TC', 'Noto Serif CJK KR', 'Source Han Sans JP', 'Source Han Sans SC',
                 'Source Han Sans TC', 'Source Han Sans KR', 'Hiragino Kaku Gothic ProN', 'Yu Gothic',
                 'PingFang SC', 'Microsoft YaHei', 'Microsoft JhengHei', 'Malgun Gothic', sans-serif;
}

code,
pre {
    font-family: 'Noto Sans Mono CJK JP', 'Noto Sans Mono', 'Source Code Pro', 'Roboto Mono',
                 'Menlo', 'Consolas', 'monospace';
}
"#;

struct WorkingDirGuard {
    original: Option<std::path::PathBuf>,
}

impl WorkingDirGuard {
    fn change_to(target: &Path) -> anyhow::Result<Self> {
        let original =
            std::env::current_dir().context("unable to read current working directory")?;
        std::env::set_current_dir(target).with_context(|| {
            format!("failed to change working directory to {}", target.display())
        })?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for WorkingDirGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            if let Err(error) = std::env::set_current_dir(&original) {
                tracing::error!(
                    "failed to restore working directory to {}: {}",
                    original.display(),
                    error
                );
            }
        }
    }
}

pub struct DocumentDownload {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentDownloadFormat {
    Archive,
    Markdown,
    Html,
    Html5,
    Pdf,
    Docx,
    Latex,
    Beamer,
    Context,
    Man,
    MediaWiki,
    Dokuwiki,
    Textile,
    Org,
    Texinfo,
    Opml,
    Docbook,
    OpenDocument,
    Odt,
    Rtf,
    Epub,
    Epub3,
    Fb2,
    Asciidoc,
    Icml,
    Slidy,
    Slideous,
    Dzslides,
    Revealjs,
    S5,
    Json,
    Plain,
    Commonmark,
    CommonmarkX,
    MarkdownStrict,
    MarkdownPhpextra,
    MarkdownGithub,
    Rst,
    Native,
    Haddock,
}

impl DocumentDownloadFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            DocumentDownloadFormat::Archive => "zip",
            DocumentDownloadFormat::Markdown => "md",
            DocumentDownloadFormat::Html => "html",
            DocumentDownloadFormat::Html5 => "html",
            DocumentDownloadFormat::Pdf => "pdf",
            DocumentDownloadFormat::Docx => "docx",
            DocumentDownloadFormat::Latex => "tex",
            DocumentDownloadFormat::Beamer => "tex",
            DocumentDownloadFormat::Context => "tex",
            DocumentDownloadFormat::Man => "man",
            DocumentDownloadFormat::MediaWiki => "mediawiki",
            DocumentDownloadFormat::Dokuwiki => "txt",
            DocumentDownloadFormat::Textile => "textile",
            DocumentDownloadFormat::Org => "org",
            DocumentDownloadFormat::Texinfo => "texi",
            DocumentDownloadFormat::Opml => "opml",
            DocumentDownloadFormat::Docbook => "xml",
            DocumentDownloadFormat::OpenDocument => "fodt",
            DocumentDownloadFormat::Odt => "odt",
            DocumentDownloadFormat::Rtf => "rtf",
            DocumentDownloadFormat::Epub | DocumentDownloadFormat::Epub3 => "epub",
            DocumentDownloadFormat::Fb2 => "fb2",
            DocumentDownloadFormat::Asciidoc => "adoc",
            DocumentDownloadFormat::Icml => "icml",
            DocumentDownloadFormat::Slidy
            | DocumentDownloadFormat::Slideous
            | DocumentDownloadFormat::Dzslides
            | DocumentDownloadFormat::Revealjs
            | DocumentDownloadFormat::S5 => "html",
            DocumentDownloadFormat::Json => "json",
            DocumentDownloadFormat::Plain => "txt",
            DocumentDownloadFormat::Commonmark
            | DocumentDownloadFormat::CommonmarkX
            | DocumentDownloadFormat::MarkdownStrict
            | DocumentDownloadFormat::MarkdownPhpextra
            | DocumentDownloadFormat::MarkdownGithub => "md",
            DocumentDownloadFormat::Rst => "rst",
            DocumentDownloadFormat::Native => "hs",
            DocumentDownloadFormat::Haddock => "txt",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            DocumentDownloadFormat::Archive => "application/zip",
            DocumentDownloadFormat::Markdown => "text/markdown; charset=utf-8",
            DocumentDownloadFormat::Html => "text/html; charset=utf-8",
            DocumentDownloadFormat::Html5 => "text/html; charset=utf-8",
            DocumentDownloadFormat::Pdf => "application/pdf",
            DocumentDownloadFormat::Docx => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            DocumentDownloadFormat::Latex
            | DocumentDownloadFormat::Beamer
            | DocumentDownloadFormat::Context => "application/x-tex",
            DocumentDownloadFormat::Man => "text/troff",
            DocumentDownloadFormat::MediaWiki
            | DocumentDownloadFormat::Dokuwiki
            | DocumentDownloadFormat::Textile
            | DocumentDownloadFormat::Org
            | DocumentDownloadFormat::Texinfo
            | DocumentDownloadFormat::Plain
            | DocumentDownloadFormat::Rst
            | DocumentDownloadFormat::Native
            | DocumentDownloadFormat::Haddock => "text/plain; charset=utf-8",
            DocumentDownloadFormat::Commonmark
            | DocumentDownloadFormat::CommonmarkX
            | DocumentDownloadFormat::MarkdownStrict
            | DocumentDownloadFormat::MarkdownPhpextra
            | DocumentDownloadFormat::MarkdownGithub => "text/markdown; charset=utf-8",
            DocumentDownloadFormat::Opml | DocumentDownloadFormat::Docbook => "application/xml",
            DocumentDownloadFormat::OpenDocument | DocumentDownloadFormat::Odt => {
                "application/vnd.oasis.opendocument.text"
            }
            DocumentDownloadFormat::Rtf => "application/rtf",
            DocumentDownloadFormat::Epub | DocumentDownloadFormat::Epub3 => "application/epub+zip",
            DocumentDownloadFormat::Fb2 => "application/x-fictionbook+xml",
            DocumentDownloadFormat::Asciidoc => "text/plain; charset=utf-8",
            DocumentDownloadFormat::Icml => "application/vnd.adobe.indesign-icml",
            DocumentDownloadFormat::Slidy
            | DocumentDownloadFormat::Slideous
            | DocumentDownloadFormat::Dzslides
            | DocumentDownloadFormat::Revealjs
            | DocumentDownloadFormat::S5 => "text/html; charset=utf-8",
            DocumentDownloadFormat::Json => "application/json",
        }
    }

    pub fn file_name(&self, base: &str) -> String {
        format!("{}.{}", base, self.extension())
    }

    fn needs_pandoc(&self) -> bool {
        !matches!(
            self,
            DocumentDownloadFormat::Archive | DocumentDownloadFormat::Markdown
        )
    }
}

#[derive(Clone, Copy)]
enum PandocOutputKind {
    Pipe,
    File(&'static str),
}

#[derive(Clone)]
struct PandocCommandConfig {
    output_format: OutputFormat,
    destination: PandocOutputKind,
    standalone: bool,
    self_contained: bool,
    pdf_engine: Option<&'static str>,
    pdf_engine_opts: &'static [&'static str],
    include_default_css: bool,
}

impl PandocCommandConfig {
    fn for_format(format: DocumentDownloadFormat) -> Option<Self> {
        use DocumentDownloadFormat::*;
        let config = match format {
            Archive | Markdown => return None,
            Html => Self {
                output_format: OutputFormat::Html,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Html5 => Self {
                output_format: OutputFormat::Html5,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Pdf => Self {
                output_format: OutputFormat::Pdf,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: true,
                pdf_engine: Some("wkhtmltopdf"),
                pdf_engine_opts: &["--enable-local-file-access"],
            },
            Docx => Self {
                output_format: OutputFormat::Docx,
                destination: PandocOutputKind::File("document.docx"),
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Latex => Self {
                output_format: OutputFormat::Latex,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Beamer => Self {
                output_format: OutputFormat::Beamer,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Context => Self {
                output_format: OutputFormat::Context,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Man => Self {
                output_format: OutputFormat::Man,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MediaWiki => Self {
                output_format: OutputFormat::MediaWiki,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Dokuwiki => Self {
                output_format: OutputFormat::Dokuwiki,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Textile => Self {
                output_format: OutputFormat::Textile,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Org => Self {
                output_format: OutputFormat::Org,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Texinfo => Self {
                output_format: OutputFormat::Texinfo,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Opml => Self {
                output_format: OutputFormat::Opml,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Docbook => Self {
                output_format: OutputFormat::Docbook,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            OpenDocument => Self {
                output_format: OutputFormat::OpenDocument,
                destination: PandocOutputKind::File("document.odt"),
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Odt => Self {
                output_format: OutputFormat::Odt,
                destination: PandocOutputKind::File("document.odt"),
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Rtf => Self {
                output_format: OutputFormat::Rtf,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Epub => Self {
                output_format: OutputFormat::Epub,
                destination: PandocOutputKind::File("document.epub"),
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Epub3 => Self {
                output_format: OutputFormat::Epub3,
                destination: PandocOutputKind::File("document.epub"),
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Fb2 => Self {
                output_format: OutputFormat::Fb2,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Asciidoc => Self {
                output_format: OutputFormat::Asciidoc,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Icml => Self {
                output_format: OutputFormat::Icml,
                destination: PandocOutputKind::File("document.icml"),
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Slidy => Self {
                output_format: OutputFormat::Slidy,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Slideous => Self {
                output_format: OutputFormat::Slideous,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Dzslides => Self {
                output_format: OutputFormat::Dzslides,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Revealjs => Self {
                output_format: OutputFormat::Revealjs,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            S5 => Self {
                output_format: OutputFormat::S5,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Json => Self {
                output_format: OutputFormat::Json,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Plain => Self {
                output_format: OutputFormat::Plain,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Commonmark => Self {
                output_format: OutputFormat::Commonmark,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            CommonmarkX => Self {
                output_format: OutputFormat::CommonmarkX,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownStrict => Self {
                output_format: OutputFormat::MarkdownStrict,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownPhpextra => Self {
                output_format: OutputFormat::MarkdownPhpextra,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownGithub => Self {
                output_format: OutputFormat::MarkdownGithub,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Rst => Self {
                output_format: OutputFormat::Rst,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Native => Self {
                output_format: OutputFormat::Native,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Haddock => Self {
                output_format: OutputFormat::Haddock,
                destination: PandocOutputKind::Pipe,
                standalone: false,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
        };
        Some(config)
    }
}

#[derive(Debug)]
struct DocumentDownloadAssets {
    safe_title: String,
    display_title: Option<String>,
    markdown: Vec<u8>,
    attachments: Vec<DocumentAttachment>,
}

impl DocumentDownloadAssets {
    fn new(
        display_title: Option<String>,
        safe_title: String,
        markdown: Vec<u8>,
        attachments: Vec<DocumentAttachment>,
    ) -> Self {
        Self {
            safe_title,
            display_title,
            markdown,
            attachments,
        }
    }

    fn file_name(&self, format: DocumentDownloadFormat) -> String {
        format.file_name(&self.safe_title)
    }

    fn markdown_bytes(&self) -> &[u8] {
        &self.markdown
    }

    fn attachments(&self) -> &[DocumentAttachment] {
        &self.attachments
    }

    fn markdown_string(&self) -> anyhow::Result<String> {
        String::from_utf8(self.markdown.clone()).context("document markdown is not valid UTF-8")
    }

    fn display_title(&self) -> Option<&str> {
        self.display_title.as_deref()
    }
}

#[derive(Debug)]
struct DocumentAttachment {
    relative_path: String,
    bytes: Vec<u8>,
}

impl DocumentAttachment {
    fn new(relative_path: String, bytes: Vec<u8>) -> Self {
        Self {
            relative_path,
            bytes,
        }
    }

    fn relative_path(&self) -> &str {
        &self.relative_path
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    async fn materialize_under(&self, root: &Path) -> anyhow::Result<()> {
        let clean_path = Path::new(self.relative_path());
        if clean_path.as_os_str().is_empty() {
            return Ok(());
        }
        let target = root.join(clean_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to prepare {}", parent.display()))?;
        }
        fs::write(&target, self.as_slice())
            .await
            .with_context(|| format!("failed to write attachment {}", self.relative_path()))?;
        Ok(())
    }
}

pub struct DownloadDocument<'a, D, F, S, RT, A, SH>
where
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
    RT: RealtimeEngine + ?Sized,
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
    RT: RealtimeEngine + ?Sized,
    A: AccessRepository + ?Sized,
    SH: ShareAccessPort + ?Sized,
{
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

        self.realtime.force_save_to_fs(&doc_id.to_string()).await?;

        let markdown_path = self.storage.build_doc_file_path(doc_id).await?;
        let doc_dir = markdown_path
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("document directory missing"))?;
        let markdown_bytes = self.storage.read_bytes(markdown_path.as_path()).await?;

        let stored_attachments = self.files.list_storage_paths_for_document(doc_id).await?;
        let mut attachments: Vec<DocumentAttachment> = Vec::new();
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
            attachments.push(DocumentAttachment::new(rel_str, data));
        }

        let safe_title = sanitize_filename(&document.title);
        let display_title = {
            let trimmed = document.title.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };
        let assets = DocumentDownloadAssets::new(display_title, safe_title, markdown_bytes, attachments);
        let bytes = match format {
            DocumentDownloadFormat::Archive => build_archive(&assets)?,
            DocumentDownloadFormat::Markdown => assets.markdown_bytes().to_vec(),
            _ if format.needs_pandoc() => render_with_pandoc(format, &assets)
                .await
                .with_context(|| format!("pandoc conversion failed for format {:?}", format))?,
            _ => unreachable!("covered formats"),
        };

        let download = DocumentDownload {
            filename: assets.file_name(format),
            content_type: format.content_type().to_string(),
            bytes,
        };

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

fn build_archive(assets: &DocumentDownloadAssets) -> anyhow::Result<Vec<u8>> {
    let markdown_entry = format!("{}/{}.md", assets.safe_title, assets.safe_title);
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        zip.start_file(markdown_entry, options)?;
        zip.write_all(assets.markdown_bytes())?;
        for attachment in assets.attachments() {
            let entry_path = format!(
                "{}/{}",
                assets.safe_title,
                attachment.relative_path().trim_start_matches('/')
            );
            zip.start_file(entry_path, options)?;
            zip.write_all(attachment.as_slice())?;
        }
        zip.finish()?;
    }
    Ok(cursor.into_inner())
}

async fn render_with_pandoc(
    format: DocumentDownloadFormat,
    assets: &DocumentDownloadAssets,
) -> anyhow::Result<Vec<u8>> {
    let tmp_dir = tempdir().context("unable to create temporary directory for pandoc")?;
    let markdown_source = assets.markdown_string()?;
    let display_title = assets.display_title().map(|s| s.to_owned());

    for attachment in assets.attachments() {
        attachment.materialize_under(tmp_dir.path()).await?;
    }

    let resource_dir = tmp_dir.path().to_path_buf();
    let config = PandocCommandConfig::for_format(format)
        .ok_or_else(|| anyhow::anyhow!("unsupported pandoc format {:?}", format))?;
    let format_copy = format;
    let output_bytes = task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let mut pandoc_cmd = pandoc::new();
        pandoc_cmd.set_input(InputKind::Pipe(markdown_source));
        pandoc_cmd.set_input_format(InputFormat::Markdown, Vec::new());
        pandoc_cmd.add_option(PandocOption::ResourcePath(vec![resource_dir.clone()]));
        pandoc_cmd.add_option(PandocOption::Meta(
            "title".to_string(),
            Some(String::new()),
        ));
        if let Some(ref title) = display_title {
            if !title.is_empty() {
                pandoc_cmd.add_option(PandocOption::Meta(
                    "pagetitle".to_string(),
                    Some(title.clone()),
                ));
            }
        }

        pandoc_cmd.set_output_format(config.output_format, Vec::new());
        match config.destination {
            PandocOutputKind::Pipe => {
                pandoc_cmd.set_output(OutputKind::Pipe);
            }
            PandocOutputKind::File(file_name) => {
                let target = tmp_dir.path().join(file_name);
                pandoc_cmd.set_output(OutputKind::File(target));
            }
        }
        if config.standalone {
            pandoc_cmd.add_option(PandocOption::Standalone);
        }
        if config.self_contained {
            pandoc_cmd.add_option(PandocOption::SelfContained);
        }
        if config.include_default_css {
            let css_path = resource_dir.join("refmd-defaults.css");
            std::fs::write(&css_path, DEFAULT_PDF_CSS).with_context(|| {
                format!("failed to write temporary CSS file {}", css_path.display())
            })?;
            pandoc_cmd.add_option(PandocOption::Css(css_path.to_string_lossy().to_string()));
        }
        let mut pdf_engine_opts: Vec<String> = config
            .pdf_engine_opts
            .iter()
            .map(|opt| opt.to_string())
            .collect();
        if config.pdf_engine.is_some() {
            pdf_engine_opts.push("--allow".to_string());
            pdf_engine_opts.push(resource_dir.display().to_string());
        }
        if let Some(engine) = config.pdf_engine {
            pandoc_cmd.add_option(PandocOption::PdfEngine(PathBuf::from(engine)));
        }
        for opt in pdf_engine_opts {
            pandoc_cmd.add_option(PandocOption::PdfEngineOpt(opt));
        }

        let _lock = PANDOC_WORKDIR_LOCK.lock().unwrap();
        let _cwd_guard = WorkingDirGuard::change_to(&resource_dir)?;

        let output = pandoc_cmd.execute().map_err(|err| match err {
            pandoc::PandocError::PandocNotFound => anyhow::anyhow!(
                "pandoc executable not found in PATH; install pandoc to enable {} export",
                format_copy.extension()
            ),
            pandoc::PandocError::IoErr(io_err) => anyhow::Error::new(io_err),
            pandoc::PandocError::Err(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::anyhow!(
                    "pandoc failed (status {}): {}",
                    output.status,
                    stderr.trim()
                )
            }
            other => anyhow::Error::new(other),
        })?;
        let bytes = match output {
            PandocOutput::ToBuffer(text) => text.into_bytes(),
            PandocOutput::ToBufferRaw(raw) => raw,
            PandocOutput::ToFile(path) => std::fs::read(&path).map_err(anyhow::Error::new)?,
        };
        Ok(bytes)
    })
    .await?
    .with_context(|| format!("pandoc conversion failed for format {:?}", format))?;

    Ok(output_bytes)
}
