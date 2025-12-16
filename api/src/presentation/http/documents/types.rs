use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::document_export::DocumentDownloadFormat;
use crate::application::dto::documents::{
    DocumentListFilter, SnapshotDiffBaseMode, SnapshotDiffSideDto, SnapshotSummaryDto,
};
use crate::application::services::documents::DocumentPatchOperation;
use crate::application::services::errors::ServiceError;
use crate::domain::documents::document as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct Document {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    pub r#type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_plugin: Option<String>,
    pub slug: String,
    pub desired_path: String,
    pub path: Option<String>,
    pub created_by: Option<Uuid>,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
    pub archived_by: Option<Uuid>,
    pub archived_parent_id: Option<Uuid>,
}

pub fn to_http_document(doc: domain::Document) -> Document {
    Document {
        id: doc.id,
        owner_id: doc.owner_id,
        workspace_id: doc.workspace_id,
        title: doc.title,
        parent_id: doc.parent_id,
        r#type: doc.doc_type,
        created_at: doc.created_at,
        updated_at: doc.updated_at,
        created_by_plugin: doc.created_by_plugin,
        slug: doc.slug,
        desired_path: doc.desired_path,
        path: doc.path,
        created_by: doc.created_by,
        archived_at: doc.archived_at,
        archived_by: doc.archived_by,
        archived_parent_id: doc.archived_parent_id,
    }
}

pub fn map_service_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "document_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentListResponse {
    pub items: Vec<Document>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotSummary {
    pub id: Uuid,
    pub document_id: Uuid,
    pub label: String,
    pub notes: Option<String>,
    pub kind: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    pub byte_size: i64,
    pub content_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotListResponse {
    pub items: Vec<SnapshotSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotDiffKind {
    Current,
    Snapshot,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotDiffSideResponse {
    pub kind: SnapshotDiffKind,
    pub markdown: String,
    pub snapshot: Option<SnapshotSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotDiffResponse {
    pub base: SnapshotDiffSideResponse,
    pub target: SnapshotDiffSideResponse,
    pub diff: TextDiffResult,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotDiffBaseParam {
    Auto,
    Current,
    Previous,
}

impl Default for SnapshotDiffBaseParam {
    fn default() -> Self {
        Self::Auto
    }
}

impl From<SnapshotDiffBaseParam> for SnapshotDiffBaseMode {
    fn from(value: SnapshotDiffBaseParam) -> Self {
        match value {
            SnapshotDiffBaseParam::Auto => SnapshotDiffBaseMode::Auto,
            SnapshotDiffBaseParam::Current => SnapshotDiffBaseMode::ForceCurrent,
            SnapshotDiffBaseParam::Previous => SnapshotDiffBaseMode::ForcePrevious,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotRestoreResponse {
    pub snapshot: SnapshotSummary,
}

pub fn snapshot_summary_from(record: SnapshotSummaryDto) -> SnapshotSummary {
    SnapshotSummary {
        id: record.id,
        document_id: record.document_id,
        label: record.label,
        notes: record.notes,
        kind: record.kind,
        created_at: record.created_at,
        created_by: record.created_by,
        byte_size: record.byte_size,
        content_hash: record.content_hash,
    }
}

pub fn snapshot_diff_side_response_from(side: SnapshotDiffSideDto) -> SnapshotDiffSideResponse {
    match side {
        SnapshotDiffSideDto::Current { markdown } => SnapshotDiffSideResponse {
            kind: SnapshotDiffKind::Current,
            markdown,
            snapshot: None,
        },
        SnapshotDiffSideDto::Snapshot { snapshot, markdown } => SnapshotDiffSideResponse {
            kind: SnapshotDiffKind::Snapshot,
            markdown,
            snapshot: Some(snapshot_summary_from(snapshot)),
        },
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentRequest {
    pub title: Option<String>,
    pub parent_id: Option<Uuid>,
    pub r#type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocumentRequest {
    pub title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    #[schema(value_type = Option<String>)]
    pub parent_id: DoubleOption<Uuid>,
}

impl Default for UpdateDocumentRequest {
    fn default() -> Self {
        Self {
            title: None,
            parent_id: DoubleOption::NotProvided,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DuplicateDocumentRequest {
    pub title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    #[schema(value_type = Option<String>)]
    pub parent_id: DoubleOption<Uuid>,
}

impl Default for DuplicateDocumentRequest {
    fn default() -> Self {
        Self {
            title: None,
            parent_id: DoubleOption::NotProvided,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DoubleOption<T> {
    NotProvided,
    Null,
    Some(T),
}

fn deserialize_double_option<'de, D, T>(deserializer: D) -> Result<DoubleOption<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(|opt| match opt {
        None => DoubleOption::Null,
        Some(value) => DoubleOption::Some(value),
    })
}

impl<T> Default for DoubleOption<T> {
    fn default() -> Self {
        DoubleOption::NotProvided
    }
}

#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub query: Option<String>,
    pub tag: Option<String>,
    #[serde(default)]
    pub state: Option<DocumentStateFilter>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DocumentStateFilter {
    Active,
    Archived,
    All,
}

impl From<DocumentStateFilter> for DocumentListFilter {
    fn from(value: DocumentStateFilter) -> Self {
        match value {
            DocumentStateFilter::Active => DocumentListFilter::Active,
            DocumentStateFilter::Archived => DocumentListFilter::Archived,
            DocumentStateFilter::All => DocumentListFilter::All,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocumentContentRequest {
    pub content: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DocumentPatchOperationRequest {
    Insert {
        offset: usize,
        text: String,
    },
    Delete {
        offset: usize,
        length: usize,
    },
    Replace {
        offset: usize,
        length: usize,
        text: String,
    },
}

impl From<DocumentPatchOperationRequest> for DocumentPatchOperation {
    fn from(value: DocumentPatchOperationRequest) -> Self {
        match value {
            DocumentPatchOperationRequest::Insert { offset, text } => {
                DocumentPatchOperation::Insert { offset, text }
            }
            DocumentPatchOperationRequest::Delete { offset, length } => {
                DocumentPatchOperation::Delete { offset, length }
            }
            DocumentPatchOperationRequest::Replace {
                offset,
                length,
                text,
            } => DocumentPatchOperation::Replace {
                offset,
                length,
                text,
            },
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PatchDocumentContentRequest {
    pub operations: Vec<DocumentPatchOperationRequest>,
}

#[allow(dead_code)]
#[derive(ToSchema)]
pub struct DocumentDownloadBinary(#[schema(value_type = String, format = Binary)] pub Vec<u8>);

#[allow(dead_code)]
#[derive(ToSchema)]
pub struct DocumentArchiveBinary(#[schema(value_type = String, format = Binary)] pub Vec<u8>);

#[derive(Debug, Clone, Copy, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum DownloadFormat {
    #[default]
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
    Mediawiki,
    Dokuwiki,
    Textile,
    Org,
    Texinfo,
    Opml,
    Docbook,
    Opendocument,
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

impl From<DownloadFormat> for DocumentDownloadFormat {
    fn from(value: DownloadFormat) -> Self {
        match value {
            DownloadFormat::Archive => DocumentDownloadFormat::Archive,
            DownloadFormat::Markdown => DocumentDownloadFormat::Markdown,
            DownloadFormat::Html => DocumentDownloadFormat::Html,
            DownloadFormat::Html5 => DocumentDownloadFormat::Html5,
            DownloadFormat::Pdf => DocumentDownloadFormat::Pdf,
            DownloadFormat::Docx => DocumentDownloadFormat::Docx,
            DownloadFormat::Latex => DocumentDownloadFormat::Latex,
            DownloadFormat::Beamer => DocumentDownloadFormat::Beamer,
            DownloadFormat::Context => DocumentDownloadFormat::Context,
            DownloadFormat::Man => DocumentDownloadFormat::Man,
            DownloadFormat::Mediawiki => DocumentDownloadFormat::MediaWiki,
            DownloadFormat::Dokuwiki => DocumentDownloadFormat::Dokuwiki,
            DownloadFormat::Textile => DocumentDownloadFormat::Textile,
            DownloadFormat::Org => DocumentDownloadFormat::Org,
            DownloadFormat::Texinfo => DocumentDownloadFormat::Texinfo,
            DownloadFormat::Opml => DocumentDownloadFormat::Opml,
            DownloadFormat::Docbook => DocumentDownloadFormat::Docbook,
            DownloadFormat::Opendocument => DocumentDownloadFormat::OpenDocument,
            DownloadFormat::Odt => DocumentDownloadFormat::Odt,
            DownloadFormat::Rtf => DocumentDownloadFormat::Rtf,
            DownloadFormat::Epub => DocumentDownloadFormat::Epub,
            DownloadFormat::Epub3 => DocumentDownloadFormat::Epub3,
            DownloadFormat::Fb2 => DocumentDownloadFormat::Fb2,
            DownloadFormat::Asciidoc => DocumentDownloadFormat::Asciidoc,
            DownloadFormat::Icml => DocumentDownloadFormat::Icml,
            DownloadFormat::Slidy => DocumentDownloadFormat::Slidy,
            DownloadFormat::Slideous => DocumentDownloadFormat::Slideous,
            DownloadFormat::Dzslides => DocumentDownloadFormat::Dzslides,
            DownloadFormat::Revealjs => DocumentDownloadFormat::Revealjs,
            DownloadFormat::S5 => DocumentDownloadFormat::S5,
            DownloadFormat::Json => DocumentDownloadFormat::Json,
            DownloadFormat::Plain => DocumentDownloadFormat::Plain,
            DownloadFormat::Commonmark => DocumentDownloadFormat::Commonmark,
            DownloadFormat::CommonmarkX => DocumentDownloadFormat::CommonmarkX,
            DownloadFormat::MarkdownStrict => DocumentDownloadFormat::MarkdownStrict,
            DownloadFormat::MarkdownPhpextra => DocumentDownloadFormat::MarkdownPhpextra,
            DownloadFormat::MarkdownGithub => DocumentDownloadFormat::MarkdownGithub,
            DownloadFormat::Rst => DocumentDownloadFormat::Rst,
            DownloadFormat::Native => DocumentDownloadFormat::Native,
            DownloadFormat::Haddock => DocumentDownloadFormat::Haddock,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema, Default)]
pub struct DownloadDocumentQuery {
    pub token: Option<String>,
    #[serde(default)]
    pub format: DownloadFormat,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResult {
    pub id: Uuid,
    pub title: String,
    pub document_type: String,
    pub path: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListSnapshotsQuery {
    pub token: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotDiffQuery {
    pub token: Option<String>,
    pub compare: Option<Uuid>,
    #[serde(default)]
    pub base: Option<SnapshotDiffBaseParam>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotTokenQuery {
    pub token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BacklinkInfo {
    pub document_id: String,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub link_count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BacklinksResponse {
    pub backlinks: Vec<BacklinkInfo>,
    pub total_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutgoingLink {
    pub document_id: String,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub position_start: Option<i32>,
    pub position_end: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutgoingLinksResponse {
    pub links: Vec<OutgoingLink>,
    pub total_count: usize,
}
