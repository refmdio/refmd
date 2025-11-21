use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::presentation::http::auth::{Bearer, validate_bearer};
// Config is no longer needed directly here
use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::git::{
    GitChangeItem as GitChangeDto, GitCommitInfo, GitConfigDto, GitStatusDto, GitSyncRequestDto,
    GitignoreUpdateDto, UpsertGitConfigInput,
};
use crate::application::services::errors::ServiceError;
use crate::domain::workspaces::permissions::{PERM_GIT_CONFIGURE, PERM_GIT_INIT, PERM_GIT_SYNC};
use crate::presentation::context::AppContext;
use crate::presentation::http::workspace_scope;
use tracing::error;
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

fn map_git_error(err: ServiceError) -> StatusCode {
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
    headers: HeaderMap,
) -> Result<Json<Option<GitConfigResponse>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_INIT)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let service = ctx.git_service();
    let resp: Option<GitConfigDto> = service
        .get_config(workspace_id)
        .await
        .map_err(map_git_error)?;
    let out = resp.map(Into::into);
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/git/config", tag = "Git", request_body = CreateGitConfigRequest, responses((status = 200, body = GitConfigResponse)))]
pub async fn create_or_update_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitConfigResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_INIT)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let input: UpsertGitConfigInput = req.into();
    let service = ctx.git_service();
    let resp: GitConfigDto = service
        .upsert_config(workspace_id, &input)
        .await
        .map_err(|err| match err {
            ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
            other => map_git_error(other),
        })?;
    let out: GitConfigResponse = resp.into();
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/api/git/config", tag = "Git", responses((status = 204, description = "Deleted")))]
pub async fn delete_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let service = ctx.git_service();
    service
        .delete_config(workspace_id)
        .await
        .map_err(map_git_error)?;
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
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let doc_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let service = ctx.git_service();
    let res = service
        .ignore_document(workspace_id, doc_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[utoipa::path(post, path = "/api/git/ignore/folder/{id}", params(("id" = String, Path, description = "Folder ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_folder(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let folder_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let service = ctx.git_service();
    let res = service
        .ignore_folder(workspace_id, folder_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[derive(Deserialize, ToSchema)]
pub struct AddPatternsRequest {
    pub patterns: Vec<String>,
}

#[utoipa::path(post, path = "/api/git/gitignore/patterns", tag = "Git", request_body = AddPatternsRequest, responses((status = 200, description = "OK")))]
pub async fn add_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<AddPatternsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let added = service
        .add_gitignore_patterns(workspace_id, req.patterns)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"added": added})))
}

#[utoipa::path(get, path = "/api/git/gitignore/patterns", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn get_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let patterns = service
        .get_gitignore_patterns(workspace_id)
        .await
        .map_err(map_git_error)?;
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
    headers: HeaderMap,
    Json(req): Json<CheckIgnoredRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let is_ignored = service
        .check_path_ignored(workspace_id, &req.path)
        .await
        .map_err(map_git_error)?;
    Ok(Json(
        serde_json::json!({"path": req.path, "is_ignored": is_ignored}),
    ))
}

#[utoipa::path(get, path = "/api/git/status", tag = "Git", responses((status = 200, body = GitStatus)))]
pub async fn get_status(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<GitStatus>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let dto: GitStatusDto = service
        .get_status(workspace_id)
        .await
        .map_err(map_git_error)?;
    let out: GitStatus = dto.into();
    Ok(Json(out))
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

#[utoipa::path(post, path = "/api/git/sync", tag = "Git", request_body = GitSyncRequest, responses((status = 200, body = GitSyncResponse), (status = 409, description = "Conflicts during rebase/pull")))]
pub async fn sync_now(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<GitSyncRequest>,
) -> Result<Json<GitSyncResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let out = service
        .sync_now(
            workspace_id,
            GitSyncRequestDto {
                message: req.message.clone(),
                force: req.force,
                full_scan: req.full_scan,
                skip_push: req.skip_push,
            },
        )
        .await
        .map_err(map_git_error)?;
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
    headers: HeaderMap,
) -> Result<Json<GitChangesResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let files: Vec<GitChangeDto> = service
        .get_changes(workspace_id)
        .await
        .map_err(map_git_error)?;
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

#[utoipa::path(get, path = "/api/git/history", tag = "Git", responses((status = 200, body = GitHistoryResponse)))]
pub async fn get_history(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<GitHistoryResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let commits: Vec<GitCommitInfo> = service
        .get_history(workspace_id)
        .await
        .map_err(map_git_error)?;
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
    responses((status = 200, body = [TextDiffResult]))
)]
pub async fn get_working_diff(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<TextDiffResult>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let diffs = service
        .get_working_diff(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(diffs))
}

#[utoipa::path(
    get,
    path = "/api/git/diff/commits/{from}/{to}",
    params(("from" = String, Path, description = "From"), ("to" = String, Path, description = "To")),
    tag = "Git",
    responses((status = 200, body = [TextDiffResult]))
)]
pub async fn get_commit_diff(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path((from, to)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<TextDiffResult>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let diffs = service
        .get_commit_diff(workspace_id, &from, &to)
        .await
        .map_err(map_git_error)?;
    Ok(Json(diffs))
}

// pull endpoint intentionally removed in push-only backup mode

#[utoipa::path(post, path = "/api/git/init", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn init_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    service
        .init_repository(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}

#[utoipa::path(post, path = "/api/git/deinit", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn deinit_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    service
        .deinit_repository(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}
