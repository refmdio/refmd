use application::core::services::errors::ServiceError;
use application::git::dtos::{GitConfigDto, UpsertGitConfigInput};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub fn map_git_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "git_service_error")
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitConfigResponse {
    pub id: uuid::Uuid,
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: String,
    pub auto_sync: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub remote_check: Option<GitRemoteCheckResponse>,
    /// E2EE encrypted auth data (only present for E2EE clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_auth_data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitRemoteCheckResponse {
    pub ok: bool,
    pub message: String,
    pub reason: Option<String>,
}

impl From<application::git::dtos::GitRemoteCheckDto> for GitRemoteCheckResponse {
    fn from(value: application::git::dtos::GitRemoteCheckDto) -> Self {
        Self {
            ok: value.ok,
            message: value.message,
            reason: value.reason,
        }
    }
}

impl From<GitConfigDto> for GitConfigResponse {
    fn from(d: GitConfigDto) -> Self {
        GitConfigResponse {
            id: d.id,
            repository_url: d.repository_url,
            branch_name: d.branch_name,
            auth_type: d.auth_type,
            auto_sync: d.auto_sync,
            created_at: d.created_at,
            updated_at: d.updated_at,
            remote_check: None,
            encrypted_auth_data: d.encrypted_auth_data,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateGitConfigRequest {
    pub repository_url: String,
    pub branch_name: Option<String>,
    pub auth_type: String,
    pub auth_data: serde_json::Value,
    pub auto_sync: Option<bool>,
}

impl From<CreateGitConfigRequest> for UpsertGitConfigInput {
    fn from(r: CreateGitConfigRequest) -> Self {
        UpsertGitConfigInput {
            repository_url: r.repository_url,
            branch_name: r.branch_name,
            auth_type: r.auth_type,
            auth_data: r.auth_data,
            auto_sync: r.auto_sync,
        }
    }
}
