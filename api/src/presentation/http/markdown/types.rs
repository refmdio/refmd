use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::application::services::markdown::{PlaceholderItem, RenderOptions, RenderResponse};

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, Default)]
#[serde(default)]
pub struct RenderOptionsPayload {
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

impl From<RenderOptionsPayload> for RenderOptions {
    fn from(value: RenderOptionsPayload) -> Self {
        RenderOptions {
            flavor: value.flavor,
            theme: value.theme,
            features: value.features,
            sanitize: value.sanitize,
            hardbreaks: value.hardbreaks,
            doc_id: value.doc_id,
            base_origin: value.base_origin,
            absolute_attachments: value.absolute_attachments,
            token: value.token,
        }
    }
}

impl From<RenderOptions> for RenderOptionsPayload {
    fn from(value: RenderOptions) -> Self {
        Self {
            flavor: value.flavor,
            theme: value.theme,
            features: value.features,
            sanitize: value.sanitize,
            hardbreaks: value.hardbreaks,
            doc_id: value.doc_id,
            base_origin: value.base_origin,
            absolute_attachments: value.absolute_attachments,
            token: value.token,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlaceholderItemPayload {
    pub kind: String,
    pub id: String,
    pub code: String,
}

impl From<PlaceholderItem> for PlaceholderItemPayload {
    fn from(value: PlaceholderItem) -> Self {
        Self {
            kind: value.kind,
            id: value.id,
            code: value.code,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RenderResponseBody {
    pub html: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<PlaceholderItemPayload>,
    pub hash: String,
}

impl From<RenderResponse> for RenderResponseBody {
    fn from(value: RenderResponse) -> Self {
        Self {
            html: value.html,
            placeholders: value
                .placeholders
                .into_iter()
                .map(PlaceholderItemPayload::from)
                .collect(),
            hash: value.hash,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenderRequest {
    pub text: String,
    #[serde(default)]
    pub options: RenderOptionsPayload,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenderManyRequest {
    pub items: Vec<RenderRequest>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RenderManyResponse {
    pub items: Vec<RenderResponseBody>,
}
