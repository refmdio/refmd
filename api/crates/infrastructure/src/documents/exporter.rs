use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pandoc::{self, InputFormat, InputKind, OutputFormat, OutputKind, PandocOption, PandocOutput};
use tempfile::tempdir;
use tokio::fs;
use tokio::task;
use zip::write::FileOptions;
use zip::{self, CompressionMethod};

use application::documents::dtos::{DocumentDownload, DocumentDownloadFormat};
use application::documents::ports::document_exporter::{
    DocumentExportAssets, DocumentExportAttachment, DocumentExporter,
};

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

static PANDOC_WORKDIR_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Default)]
pub struct DefaultDocumentExporter;

impl DefaultDocumentExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DocumentExporter for DefaultDocumentExporter {
    async fn export(
        &self,
        assets: DocumentExportAssets,
        format: DocumentDownloadFormat,
    ) -> anyhow::Result<DocumentDownload> {
        let bytes = match format {
            DocumentDownloadFormat::Archive => build_archive(&assets)?,
            DocumentDownloadFormat::Markdown => assets.markdown.clone(),
            _ if needs_pandoc(&format) => render_with_pandoc(format, &assets).await?,
            _ => unreachable!("unsupported format"),
        };

        Ok(DocumentDownload {
            filename: format.file_name(&assets.safe_title),
            content_type: format.content_type().to_string(),
            bytes,
        })
    }
}

fn needs_pandoc(format: &DocumentDownloadFormat) -> bool {
    !matches!(
        format,
        DocumentDownloadFormat::Archive | DocumentDownloadFormat::Markdown
    )
}

fn build_archive(assets: &DocumentExportAssets) -> anyhow::Result<Vec<u8>> {
    let markdown_entry = format!("{}/{}.md", assets.safe_title, assets.safe_title);
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        zip.start_file(markdown_entry, options)?;
        zip.write_all(&assets.markdown)?;
        for attachment in &assets.attachments {
            let entry = format!(
                "{}/{}",
                assets.safe_title,
                attachment_trimmed_path(attachment)
            );
            zip.start_file(entry, options)?;
            zip.write_all(&attachment.bytes)?;
        }
        zip.finish()?;
    }
    Ok(cursor.into_inner())
}

async fn render_with_pandoc(
    format: DocumentDownloadFormat,
    assets: &DocumentExportAssets,
) -> anyhow::Result<Vec<u8>> {
    let tmp_dir = tempdir().context("unable to create temporary directory for pandoc")?;
    let markdown_source = markdown_string(assets)?;
    let display_title = assets.display_title.clone();

    for attachment in &assets.attachments {
        materialize_attachment_under(attachment, tmp_dir.path()).await?;
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
        pandoc_cmd.add_option(PandocOption::Meta("title".to_string(), Some(String::new())));
        if let Some(title) = display_title.as_deref() {
            if !title.is_empty() {
                pandoc_cmd.add_option(PandocOption::Meta(
                    "pagetitle".to_string(),
                    Some(title.to_string()),
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

fn markdown_string(assets: &DocumentExportAssets) -> anyhow::Result<String> {
    String::from_utf8(assets.markdown.clone())
        .map_err(|_| anyhow::anyhow!("document markdown is not valid UTF-8"))
}

async fn materialize_attachment_under(
    attachment: &DocumentExportAttachment,
    root: &Path,
) -> anyhow::Result<()> {
    let clean_path = Path::new(&attachment.relative_path);
    if clean_path.as_os_str().is_empty() {
        return Ok(());
    }
    let target = root.join(clean_path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to prepare {}", parent.display()))?;
    }
    fs::write(&target, &attachment.bytes)
        .await
        .with_context(|| format!("failed to write attachment {}", attachment.relative_path))?;
    Ok(())
}

fn attachment_trimmed_path(attachment: &DocumentExportAttachment) -> &str {
    attachment.relative_path.trim_start_matches('/')
}

struct WorkingDirGuard {
    original: Option<PathBuf>,
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
                self_contained: true,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Epub3 => Self {
                output_format: OutputFormat::Epub3,
                destination: PandocOutputKind::File("document.epub"),
                standalone: true,
                self_contained: true,
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
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Plain => Self {
                output_format: OutputFormat::Plain,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Commonmark => Self {
                output_format: OutputFormat::Commonmark,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            CommonmarkX => Self {
                output_format: OutputFormat::CommonmarkX,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownStrict => Self {
                output_format: OutputFormat::MarkdownStrict,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownPhpextra => Self {
                output_format: OutputFormat::MarkdownPhpextra,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            MarkdownGithub => Self {
                output_format: OutputFormat::MarkdownGithub,
                destination: PandocOutputKind::Pipe,
                standalone: true,
                self_contained: false,
                include_default_css: false,
                pdf_engine: None,
                pdf_engine_opts: &[],
            },
            Rst => Self {
                output_format: OutputFormat::Rst,
                destination: PandocOutputKind::Pipe,
                standalone: true,
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

#[derive(Clone, Copy)]
enum PandocOutputKind {
    Pipe,
    File(&'static str),
}
