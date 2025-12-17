use application::git::dtos::UpsertGitConfigInput;
use application::git::dtos::{
    GitChangeItem as GitChangeDto, GitCommitInfo, GitConfigDto, GitPullConflictItemDto,
    GitPullResolutionDto, GitPullSessionDto, GitStatusDto, GitignoreUpdateDto,
};
use application::core::services::errors::ServiceError;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;

pub fn map_git_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "git_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitignoreUpdateResponse {
    pub added: usize,
    pub patterns: Vec<String>,
}

impl From<GitignoreUpdateDto> for GitignoreUpdateResponse {
    fn from(value: GitignoreUpdateDto) -> Self {
        Self {
            added: value.added,
            patterns: value.patterns,
        }
    }
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateGitConfigRequest {
    pub repository_url: Option<String>,
    pub branch_name: Option<String>,
    pub auth_type: Option<String>,
    pub auth_data: Option<serde_json::Value>,
    pub auto_sync: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitPullResolution {
    pub path: String,
    pub choice: String,
    pub content: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GitPullRequest {
    pub resolutions: Option<Vec<GitPullResolution>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitPullConflictItem {
    pub path: String,
    pub is_binary: bool,
    pub ours: Option<String>,
    pub theirs: Option<String>,
    pub base: Option<String>,
    pub document_id: Option<uuid::Uuid>,
}

impl From<GitPullConflictItemDto> for GitPullConflictItem {
    fn from(value: GitPullConflictItemDto) -> Self {
        Self {
            path: value.path,
            is_binary: value.is_binary,
            ours: value.ours,
            theirs: value.theirs,
            base: value.base,
            document_id: value.document_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitPullResponse {
    pub success: bool,
    pub message: String,
    pub files_changed: i32,
    pub commit_hash: Option<String>,
    pub conflicts: Option<Vec<GitPullConflictItem>>,
    pub git_status: Option<GitStatus>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitImportResponse {
    pub success: bool,
    pub message: String,
    pub files_changed: i32,
    pub commit_hash: Option<String>,
    pub docs_created: i32,
    pub attachments_created: i32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitPullSessionResponse {
    pub session_id: uuid::Uuid,
    pub status: String,
    pub conflicts: Vec<GitPullConflictItem>,
    pub resolutions: Vec<GitPullResolution>,
    pub message: Option<String>,
}

impl From<GitPullSessionDto> for GitPullSessionResponse {
    fn from(value: GitPullSessionDto) -> Self {
        Self {
            session_id: value.id,
            status: value.status,
            conflicts: value.conflicts.into_iter().map(Into::into).collect(),
            resolutions: value
                .resolutions
                .into_iter()
                .map(|r| GitPullResolution {
                    path: r.path,
                    choice: r.choice,
                    content: r.content,
                })
                .collect(),
            message: value.message,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct GitStatus {
    pub repository_initialized: bool,
    pub has_remote: bool,
    pub current_branch: Option<String>,
    pub uncommitted_changes: u32,
    pub untracked_files: u32,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_message: Option<String>,
    pub last_sync_commit_hash: Option<String>,
    pub sync_enabled: bool,
}

impl From<GitStatusDto> for GitStatus {
    fn from(d: GitStatusDto) -> Self {
        GitStatus {
            repository_initialized: d.repository_initialized,
            has_remote: d.has_remote,
            current_branch: d.current_branch,
            uncommitted_changes: d.uncommitted_changes,
            untracked_files: d.untracked_files,
            last_sync: d.last_sync,
            last_sync_status: d.last_sync_status,
            last_sync_message: d.last_sync_message,
            last_sync_commit_hash: d.last_sync_commit_hash,
            sync_enabled: d.sync_enabled,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GitSyncRequest {
    pub message: Option<String>,
    pub force: Option<bool>,
    pub full_scan: Option<bool>,
    pub skip_push: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitSyncResponse {
    pub success: bool,
    pub message: String,
    pub commit_hash: Option<String>,
    pub files_changed: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitChangeItem {
    pub path: String,
    pub status: String,
}

impl From<GitChangeDto> for GitChangeItem {
    fn from(value: GitChangeDto) -> Self {
        GitChangeItem {
            path: value.path,
            status: value.status,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitChangesResponse {
    pub files: Vec<GitChangeItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitCommitItem {
    pub hash: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub time: chrono::DateTime<chrono::Utc>,
}

impl From<GitCommitInfo> for GitCommitItem {
    fn from(value: GitCommitInfo) -> Self {
        GitCommitItem {
            hash: value.hash,
            message: value.message,
            author_name: value.author_name,
            author_email: value.author_email,
            time: value.time,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitHistoryResponse {
    pub commits: Vec<GitCommitItem>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddPatternsRequest {
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckIgnoredRequest {
    pub path: String,
}

impl From<GitPullResolution> for GitPullResolutionDto {
    fn from(value: GitPullResolution) -> Self {
        GitPullResolutionDto {
            path: value.path,
            choice: value.choice,
            content: value.content,
        }
    }
}
