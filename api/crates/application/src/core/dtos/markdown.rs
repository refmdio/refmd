use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(default)]
pub struct RenderOptions {
    pub flavor: Option<String>,
    pub theme: Option<String>,
    pub features: Option<Vec<String>>,
    pub sanitize: Option<bool>,
    pub hardbreaks: Option<bool>,
    pub doc_id: Option<uuid::Uuid>,
    pub base_origin: Option<String>,
    pub absolute_attachments: Option<bool>,
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
