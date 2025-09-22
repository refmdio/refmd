use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::presentation::http::auth::{Bearer, validate_bearer};
// Config is no longer needed directly here
use crate::application::dto::git::{
    DiffLine as DiffLineDto, DiffLineType as DiffLineTypeDto, DiffResult as DiffResultDto,
    GitChangeItem as GitChangeDto, GitCommitInfo, GitConfigDto, GitStatusDto, GitSyncRequestDto,
    UpsertGitConfigInput,
};
use crate::application::use_cases::git::delete_config::DeleteGitConfig;
use crate::application::use_cases::git::get_config::GetGitConfig;
use crate::application::use_cases::git::get_status::GetGitStatus;
use crate::application::use_cases::git::init_repo::{DeinitRepo, InitRepo};
use crate::application::use_cases::git::upsert_config::UpsertGitConfig;
use crate::bootstrap::app_context::AppContext;
use uuid::Uuid;

// Uses AppContext as router state

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/git/config",
            get(get_config)
                .post(create_or_update_config)
                .delete(delete_config),
        )
        .route("/git/status", get(get_status))
        .route("/git/changes", get(get_changes))
        .route("/git/history", get(get_history))
        .route("/git/diff/working", get(get_working_diff))
        .route("/git/diff/commits/:from/:to", get(get_commit_diff))
        .route("/git/sync", post(sync_now))
        .route("/git/init", post(init_repository))
        .route("/git/deinit", post(deinit_repository))
        .route("/git/ignore/doc/:id", post(ignore_document))
        .route("/git/ignore/folder/:id", post(ignore_folder))
        .route(
            "/git/gitignore/patterns",
            get(get_gitignore_patterns).post(add_gitignore_patterns),
        )
        .route("/git/gitignore/check", post(check_path_ignored))
        .with_state(ctx)
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

#[utoipa::path(get, path = "/api/git/config", tag = "Git", responses((status = 200, body = Option<GitConfigResponse>)))]
pub async fn get_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<Option<GitConfigResponse>>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let uc = GetGitConfig {
        repo: repo.as_ref(),
    };
    let resp: Option<GitConfigDto> = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let out = resp.map(Into::into);
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/git/config", tag = "Git", request_body = CreateGitConfigRequest, responses((status = 200, body = GitConfigResponse)))]
pub async fn create_or_update_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitConfigResponse>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let workspace = ctx.git_workspace();
    let uc = UpsertGitConfig {
        repo: repo.as_ref(),
        storage: storage.as_ref(),
        gitignore: gitignore.as_ref(),
        workspace: workspace.as_ref(),
    };
    let input: UpsertGitConfigInput = req.into();
    let resp: GitConfigDto = uc
        .execute(user_id, &input)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let out: GitConfigResponse = resp.into();
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/api/git/config", tag = "Git", responses((status = 204, description = "Deleted")))]
pub async fn delete_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<StatusCode, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let uc = DeleteGitConfig {
        repo: repo.as_ref(),
    };
    let _ = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
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

// Diff models are provided in application::dto::git
// strip_user_prefix moved to application/use_cases/git/helpers

// compute_doc_patterns_with is provided in use-cases layer; no local definition here

// compute_doc_patterns: no longer used (use-case handles patterns via shared helper)

#[utoipa::path(post, path = "/api/git/ignore/doc/{id}", params(("id" = String, Path, description = "Document ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let doc_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let files = ctx.files_repo();
    let docs = ctx.document_repo();
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::ignore_document::IgnoreDocument {
        storage: storage.as_ref(),
        files: files.as_ref(),
        docs: docs.as_ref(),
        gitignore: gitignore.as_ref(),
        workspace: workspace.as_ref(),
    };
    let res = uc
        .execute(user_id, doc_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::json!({"added": res.added, "patterns": res.patterns}),
    ))
}

#[utoipa::path(post, path = "/api/git/ignore/folder/{id}", params(("id" = String, Path, description = "Folder ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_folder(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let folder_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let files = ctx.files_repo();
    let docs = ctx.document_repo();
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::ignore_folder::IgnoreFolder {
        storage: storage.as_ref(),
        files: files.as_ref(),
        docs: docs.as_ref(),
        gitignore: gitignore.as_ref(),
        workspace: workspace.as_ref(),
    };
    let res = uc
        .execute(user_id, folder_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::json!({"added": res.added, "patterns": res.patterns}),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct AddPatternsRequest {
    pub patterns: Vec<String>,
}

#[utoipa::path(post, path = "/api/git/gitignore/patterns", tag = "Git", request_body = AddPatternsRequest, responses((status = 200, description = "OK")))]
pub async fn add_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<AddPatternsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::gitignore_patterns::AddGitignorePatterns {
        storage: storage.as_ref(),
        gitignore: gitignore.as_ref(),
        workspace: workspace.as_ref(),
    };
    let added = uc
        .execute(user_id, req.patterns)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"added": added})))
}

#[utoipa::path(get, path = "/api/git/gitignore/patterns", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn get_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let uc = crate::application::use_cases::git::gitignore_patterns::GetGitignorePatterns {
        storage: storage.as_ref(),
        gitignore: gitignore.as_ref(),
    };
    let patterns = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"patterns": patterns})))
}

#[derive(Deserialize, ToSchema)]
pub struct CheckIgnoredRequest {
    pub path: String,
}

#[utoipa::path(post, path = "/api/git/gitignore/check", tag = "Git", request_body = CheckIgnoredRequest, responses((status = 200, description = "OK")))]
pub async fn check_path_ignored(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<CheckIgnoredRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let storage = ctx.storage_port();
    let gitignore = ctx.gitignore_port();
    let uc = crate::application::use_cases::git::gitignore_patterns::CheckPathIgnored {
        gitignore: gitignore.as_ref(),
        storage: storage.as_ref(),
    };
    let is_ignored = uc
        .execute(user_id, &req.path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        serde_json::json!({"path": req.path, "is_ignored": is_ignored}),
    ))
}

#[utoipa::path(get, path = "/api/git/status", tag = "Git", responses((status = 200, body = GitStatus)))]
pub async fn get_status(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<GitStatus>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let workspace = ctx.git_workspace();
    let uc = GetGitStatus {
        repo: repo.as_ref(),
        workspace: workspace.as_ref(),
    };
    let dto: GitStatusDto = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let out: GitStatus = dto.into();
    Ok(Json(out))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GitSyncRequest {
    pub message: Option<String>,
    pub force: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitSyncResponse {
    pub success: bool,
    pub message: String,
    pub commit_hash: Option<String>,
    pub files_changed: u32,
}

#[utoipa::path(post, path = "/api/git/sync", tag = "Git", request_body = GitSyncRequest, responses((status = 200, body = GitSyncResponse), (status = 409, description = "Conflicts during rebase/pull")))]
pub async fn sync_now(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<GitSyncRequest>,
) -> Result<Json<GitSyncResponse>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::sync_now::SyncNow {
        workspace: workspace.as_ref(),
        repo: repo.as_ref(),
    };
    let out = uc
        .execute(
            user_id,
            GitSyncRequestDto {
                message: req.message.clone(),
                force: req.force,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error=?e, "git_sync_failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(GitSyncResponse {
        success: out.success,
        message: out.message,
        commit_hash: out.commit_hash,
        files_changed: out.files_changed,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitChangeItem {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitChangesResponse {
    pub files: Vec<GitChangeItem>,
}

#[utoipa::path(get, path = "/api/git/changes", tag = "Git", responses((status = 200, body = GitChangesResponse)))]
pub async fn get_changes(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<GitChangesResponse>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::get_changes::GetChanges {
        workspace: workspace.as_ref(),
    };
    let files: Vec<GitChangeDto> = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items = files
        .into_iter()
        .map(|c| GitChangeItem {
            path: c.path,
            status: c.status,
        })
        .collect();
    Ok(Json(GitChangesResponse { files: items }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitCommitItem {
    pub hash: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GitHistoryResponse {
    pub commits: Vec<GitCommitItem>,
}

#[derive(Debug, Serialize, ToSchema, Clone)]
#[serde(rename_all = "lowercase")]
pub enum GitDiffLineType {
    Added,
    Deleted,
    Context,
}

impl From<DiffLineTypeDto> for GitDiffLineType {
    fn from(value: DiffLineTypeDto) -> Self {
        match value {
            DiffLineTypeDto::Added => GitDiffLineType::Added,
            DiffLineTypeDto::Deleted => GitDiffLineType::Deleted,
            DiffLineTypeDto::Context => GitDiffLineType::Context,
        }
    }
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct GitDiffLine {
    pub line_type: GitDiffLineType,
    pub old_line_number: Option<u32>,
    pub new_line_number: Option<u32>,
    pub content: String,
}

impl From<DiffLineDto> for GitDiffLine {
    fn from(value: DiffLineDto) -> Self {
        Self {
            line_type: value.line_type.into(),
            old_line_number: value.old_line_number,
            new_line_number: value.new_line_number,
            content: value.content,
        }
    }
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct GitDiffResult {
    pub file_path: String,
    pub diff_lines: Vec<GitDiffLine>,
    pub old_content: Option<String>,
    pub new_content: Option<String>,
}

impl From<DiffResultDto> for GitDiffResult {
    fn from(value: DiffResultDto) -> Self {
        Self {
            file_path: value.file_path,
            diff_lines: value
                .diff_lines
                .into_iter()
                .map(GitDiffLine::from)
                .collect(),
            old_content: value.old_content,
            new_content: value.new_content,
        }
    }
}

#[utoipa::path(get, path = "/api/git/history", tag = "Git", responses((status = 200, body = GitHistoryResponse)))]
pub async fn get_history(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<GitHistoryResponse>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::get_history::GetHistory {
        workspace: workspace.as_ref(),
    };
    let commits: Vec<GitCommitInfo> = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let out = commits
        .into_iter()
        .map(|c| GitCommitItem {
            hash: c.hash,
            message: c.message,
            author_name: c.author_name,
            author_email: c.author_email,
            time: c.time,
        })
        .collect();
    Ok(Json(GitHistoryResponse { commits: out }))
}

#[utoipa::path(
    get,
    path = "/api/git/diff/working",
    tag = "Git",
    responses((status = 200, body = [GitDiffResult]))
)]
pub async fn get_working_diff(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<Vec<GitDiffResult>>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::get_working_diff::GetWorkingDiff {
        workspace: workspace.as_ref(),
    };
    let diffs = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let body = diffs.into_iter().map(GitDiffResult::from).collect();
    Ok(Json(body))
}

#[utoipa::path(
    get,
    path = "/api/git/diff/commits/{from}/{to}",
    params(("from" = String, Path, description = "From"), ("to" = String, Path, description = "To")),
    tag = "Git",
    responses((status = 200, body = [GitDiffResult]))
)]
pub async fn get_commit_diff(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    axum::extract::Path((from, to)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<GitDiffResult>>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx.git_workspace();
    let uc = crate::application::use_cases::git::get_commit_diff::GetCommitDiff {
        workspace: workspace.as_ref(),
    };
    let diffs = uc
        .execute(user_id, from, to)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let body = diffs.into_iter().map(GitDiffResult::from).collect();
    Ok(Json(body))
}

// pull endpoint intentionally removed in push-only backup mode

#[utoipa::path(post, path = "/api/git/init", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn init_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.git_repo();
    let gitignore = ctx.gitignore_port();
    let storage = ctx.storage_port();
    let workspace = ctx.git_workspace();
    let uc = InitRepo {
        repo: repo.as_ref(),
        storage: storage.as_ref(),
        gitignore: gitignore.as_ref(),
        workspace: workspace.as_ref(),
    };
    uc.execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"success":true})))
}

#[utoipa::path(post, path = "/api/git/deinit", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn deinit_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx.git_workspace();
    let uc = DeinitRepo {
        workspace: workspace.as_ref(),
    };
    uc.execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"success":true})))
}
