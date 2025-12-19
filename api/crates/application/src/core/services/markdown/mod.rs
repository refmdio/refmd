use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(default)]
pub struct RenderOptions {
    pub flavor: Option<String>,
    pub theme: Option<String>,
    pub features: Option<Vec<String>>,
    pub sanitize: Option<bool>,
    /// If true, convert soft line breaks (single newlines) into <br> tags
    pub hardbreaks: Option<bool>,
    /// If provided, rewrite attachment-relative links/images to absolute under /uploads/{doc_id}
    pub doc_id: Option<uuid::Uuid>,
    /// If provided, prefix absolute URLs with this origin (e.g., https://api.example.com)
    pub base_origin: Option<String>,
    /// If true, rewrite attachment URLs (./attachments/, attachments/, /uploads/)
    pub absolute_attachments: Option<bool>,
    /// Optional share token to append as query (?token=...)
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PlaceholderItem {
    pub kind: String,
    pub id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct RenderResponse {
    pub html: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<PlaceholderItem>,
    pub hash: String,
}

