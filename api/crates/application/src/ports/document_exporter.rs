use async_trait::async_trait;

use crate::contracts::document_export::{DocumentDownload, DocumentDownloadFormat};

#[derive(Debug, Clone)]
pub struct DocumentExportAttachment {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DocumentExportAssets {
    pub safe_title: String,
    pub display_title: Option<String>,
    pub markdown: Vec<u8>,
    pub attachments: Vec<DocumentExportAttachment>,
}

#[async_trait]
pub trait DocumentExporter: Send + Sync {
    async fn export(
        &self,
        assets: DocumentExportAssets,
        format: DocumentDownloadFormat,
    ) -> anyhow::Result<DocumentDownload>;
}
