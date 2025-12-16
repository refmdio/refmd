use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::contracts::plugins::ExecResult;
use application::services::plugins::management::PluginManifestItem;

pub use super::util::ensure_valid_plugin_id;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordsPath {
    pub plugin: String,
    pub doc_id: Uuid,
    pub kind: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecordsResponse {
    pub items: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResultResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub effects: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl From<ExecResult> for ExecResultResponse {
    fn from(value: ExecResult) -> Self {
        Self {
            ok: value.ok,
            data: value.data,
            effects: value.effects,
            error: value.error,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ManifestItem {
    pub id: String,
    pub name: Option<String>,
    pub version: String,
    pub scope: String,
    pub mounts: Vec<String>,
    pub frontend: serde_json::Value,
    pub permissions: Vec<String>,
    pub config: serde_json::Value,
    pub ui: serde_json::Value,
    pub author: Option<String>,
    pub repository: Option<String>,
}

impl From<PluginManifestItem> for ManifestItem {
    fn from(value: PluginManifestItem) -> Self {
        Self {
            id: value.id,
            name: value.name,
            version: value.version,
            scope: value.scope,
            mounts: value.mounts,
            frontend: value.frontend,
            permissions: value.permissions,
            config: value.config,
            ui: value.ui,
            author: value.author,
            repository: value.repository,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRecordBody {
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRecordPath {
    pub plugin: String,
    pub id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRecordBody {
    pub patch: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct KvPath {
    pub plugin: String,
    pub doc_id: Uuid,
    pub key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KvValueResponse {
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct KvValueBody {
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecBody {
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallFromUrlBody {
    pub url: String,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InstallResponse {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UninstallBody {
    pub id: String,
}

pub fn extract_doc_id(value: &serde_json::Value) -> Option<Uuid> {
    value
        .get("docId")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("docId"))
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
        })
}
