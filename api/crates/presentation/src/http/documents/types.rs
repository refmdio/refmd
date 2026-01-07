use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::http::error::ApiError;
use application::core::services::errors::ServiceError;
use application::documents::dtos::DocumentDownloadFormat;
use application::documents::dtos::{
    DocumentListFilter, SnapshotDiffBaseMode, SnapshotDiffSideDto, SnapshotSummaryDto,
};
use application::documents::services::DocumentPatchOperation;
use contracts::core::dtos::TextDiffResult;
use domain::documents::document as domain;

#[derive(Debug, Serialize, ToSchema)]
pub struct Document {
    pub id: Uuid,
    /// Legacy alias for `workspace_id` kept for backward compatibility with older clients.
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
    // E2EE fields
    #[serde(skip_serializing_if = "Option::is_none", rename = "encryptedTitle")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "encryptedTitleNonce")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_title_nonce: Option<String>,
}

pub fn to_http_document(doc: domain::Document) -> Document {
    use base64::Engine;
    Document {
        id: doc.id(),
        // NOTE: Older clients used `owner_id` to identify the workspace.
        owner_id: doc.workspace_id(),
        workspace_id: doc.workspace_id(),
        title: doc.title().as_str().to_string(),
        parent_id: doc.parent_id(),
        r#type: doc.doc_type().to_string(),
        created_at: doc.created_at(),
        updated_at: doc.updated_at(),
        created_by_plugin: doc.created_by_plugin().map(str::to_string),
        slug: doc.slug().as_str().to_string(),
        desired_path: doc.desired_path().as_str().to_string(),
        path: doc.path().map(str::to_string),
        created_by: doc.created_by(),
        archived_at: doc.archived_at(),
        archived_by: doc.archived_by(),
        archived_parent_id: doc.archived_parent_id(),
        encrypted_title: doc
            .encrypted_title()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
        encrypted_title_nonce: doc
            .encrypted_title_nonce()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
    }
}

pub fn map_service_error(err: ServiceError) -> ApiError {
    crate::http::error::map_service_error(err, "document_service_error")
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
    // E2EE fields
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub signature: Option<String>,
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

#[derive(Debug, Clone, Copy, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotDiffBaseParam {
    #[default]
    Auto,
    Current,
    Previous,
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

/// Response for GET /api/documents/{id}/snapshots/{snapshotId}
/// - For E2EE documents: content is encrypted, nonce is present
/// - For non-E2EE documents: content is plaintext Yjs state, nonce is None
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDetailResponse {
    pub id: Uuid,
    /// Base64 encoded Yjs snapshot (encrypted for E2EE, plaintext for non-E2EE)
    #[schema(value_type = String, format = "byte")]
    pub content: String,
    /// Base64 encoded nonce (present for E2EE documents)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub nonce: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn snapshot_summary_from(record: SnapshotSummaryDto) -> SnapshotSummary {
    use base64::Engine;
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
        nonce: record
            .nonce
            .map(|b| base64::engine::general_purpose::STANDARD.encode(&b)),
        signature: record
            .signature
            .map(|b| base64::engine::general_purpose::STANDARD.encode(&b)),
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
#[serde(rename_all = "camelCase")]
pub struct CreateDocumentRequest {
    pub title: Option<String>,
    pub parent_id: Option<Uuid>,
    pub r#type: Option<String>,
    // E2EE fields
    /// Base64 encoded encrypted title (for E2EE clients)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_title: Option<String>,
    /// Base64 encoded nonce for encrypted title
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_title_nonce: Option<String>,
    /// Encrypted DEK for this document (optional, for E2EE clients)
    #[serde(default)]
    pub dek: Option<CreateDocumentDekPayload>,
}

/// DEK payload for document creation
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDocumentDekPayload {
    /// Base64 encoded encrypted DEK
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
    /// Base64 encoded nonce
    #[schema(value_type = String, format = "byte")]
    pub nonce: String,
    /// Key version
    #[serde(default = "default_key_version")]
    pub key_version: i32,
}

fn default_key_version() -> i32 {
    1
}

impl CreateDocumentDekPayload {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>, i32), &'static str> {
        use base64::Engine;
        let encrypted_dek = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_dek)
            .map_err(|_| "invalid_encrypted_dek_base64")?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|_| "invalid_nonce_base64")?;
        Ok((encrypted_dek, nonce, self.key_version))
    }
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

#[derive(Debug, Clone, Default)]
pub enum DoubleOption<T> {
    #[default]
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
#[serde(rename_all = "camelCase")]
pub struct UpdateDocumentContentRequest {
    /// Document content (plaintext or Base64-encoded encrypted Yjs state for E2EE)
    pub content: String,
    /// Base64 encoded nonce (required for E2EE content)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub nonce: Option<String>,
    /// Base64 encoded signature for integrity verification (optional for E2EE)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub signature: Option<String>,
}

/// Patch operation for document content.
/// For plaintext mode: use `text` field.
/// For E2EE mode: use `encrypted_data` and `nonce` fields instead of `text`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DocumentPatchOperationRequest {
    Insert {
        offset: usize,
        /// Plaintext to insert (for non-E2EE documents)
        #[serde(default)]
        text: Option<String>,
        /// Base64 encoded encrypted data (for E2EE documents)
        #[serde(default)]
        #[schema(value_type = Option<String>, format = "byte")]
        encrypted_data: Option<String>,
        /// Base64 encoded nonce (required when encrypted_data is provided)
        #[serde(default)]
        #[schema(value_type = Option<String>, format = "byte")]
        nonce: Option<String>,
    },
    Delete {
        offset: usize,
        length: usize,
    },
    Replace {
        offset: usize,
        length: usize,
        /// Plaintext replacement (for non-E2EE documents)
        #[serde(default)]
        text: Option<String>,
        /// Base64 encoded encrypted data (for E2EE documents)
        #[serde(default)]
        #[schema(value_type = Option<String>, format = "byte")]
        encrypted_data: Option<String>,
        /// Base64 encoded nonce (required when encrypted_data is provided)
        #[serde(default)]
        #[schema(value_type = Option<String>, format = "byte")]
        nonce: Option<String>,
    },
}

impl DocumentPatchOperationRequest {
    /// Check if this operation is for E2EE (has encrypted_data)
    pub fn is_encrypted(&self) -> bool {
        match self {
            DocumentPatchOperationRequest::Insert { encrypted_data, .. } => encrypted_data.is_some(),
            DocumentPatchOperationRequest::Delete { .. } => false,
            DocumentPatchOperationRequest::Replace { encrypted_data, .. } => encrypted_data.is_some(),
        }
    }

    /// Convert to plaintext DocumentPatchOperation (for non-E2EE mode)
    pub fn to_plaintext_operation(&self) -> Option<DocumentPatchOperation> {
        match self {
            DocumentPatchOperationRequest::Insert { offset, text, .. } => {
                text.as_ref().map(|t| DocumentPatchOperation::Insert {
                    offset: *offset,
                    text: t.clone(),
                })
            }
            DocumentPatchOperationRequest::Delete { offset, length } => {
                Some(DocumentPatchOperation::Delete {
                    offset: *offset,
                    length: *length,
                })
            }
            DocumentPatchOperationRequest::Replace { offset, length, text, .. } => {
                text.as_ref().map(|t| DocumentPatchOperation::Replace {
                    offset: *offset,
                    length: *length,
                    text: t.clone(),
                })
            }
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchDocumentContentRequest {
    /// Patch operations. Each operation can be either plaintext (using `text` field)
    /// or encrypted (using `encryptedData` and `nonce` fields).
    #[serde(default)]
    pub operations: Vec<DocumentPatchOperationRequest>,
    /// Base64 encoded signature for integrity verification (optional for E2EE)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub signature: Option<String>,
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

/// Response for GET /api/documents/{id}/content
/// - For E2EE documents: content is encrypted, nonce is present
/// - For non-E2EE documents: content is plaintext Yjs state, nonce is None
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetContentResponse {
    /// Base64 encoded Yjs snapshot bytes (encrypted for E2EE, plaintext for non-E2EE)
    #[schema(value_type = String, format = "byte")]
    pub content: String,
    /// Base64 encoded nonce for decryption (present for E2EE documents)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub nonce: Option<String>,
}
