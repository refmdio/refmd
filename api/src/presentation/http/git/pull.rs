use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::application::dto::git::{GitPullRequestDto, GitPullResolutionDto};
use crate::application::services::errors::ServiceError;
use crate::application::services::git::FinalizePullSessionResult;
use crate::domain::workspaces::permissions::PERM_GIT_SYNC;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{Bearer, validate_bearer};
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{
    GitPullConflictItem, GitPullRequest, GitPullResolution, GitPullResponse, GitPullSessionResponse,
    map_git_error,
};

#[utoipa::path(
    post,
    path = "/api/git/pull",
    tag = "Git",
    request_body = GitPullRequest,
    responses(
        (status = 200, body = GitPullResponse),
        (status = 409, body = GitPullResponse, description = "Conflicts detected")
    )
)]
pub async fn pull_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<GitPullRequest>,
) -> Result<(StatusCode, Json<GitPullResponse>), StatusCode> {
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
    let service = ctx.git_service();
    let dto = service
        .pull_repository(
            workspace_id,
            user_id,
            GitPullRequestDto {
                resolutions: req
                    .resolutions
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| GitPullResolutionDto {
                        path: r.path,
                        choice: r.choice,
                        content: r.content,
                    })
                    .collect(),
            },
        )
        .await
        .map_err(|err| {
            let message = match &err {
                ServiceError::BadRequest("workspace_has_pending_changes") => {
                    "Workspace has pending changes. Commit, sync, or discard them before pulling."
                        .to_string()
                }
                _ => err.to_string(),
            };
            let status = map_git_error(err);
            let body = GitPullResponse {
                success: false,
                message,
                files_changed: 0,
                commit_hash: None,
                conflicts: None,
                git_status: None,
            };
            (status, body)
        });
    let dto = match dto {
        Ok(v) => v,
        Err((status, body)) => return Ok((status, Json(body))),
    };
    let conflicts = dto
        .conflicts
        .map(|items| items.into_iter().map(Into::into).collect::<Vec<_>>())
        .unwrap_or_default();
    let has_conflicts = !conflicts.is_empty();
    let status = if has_conflicts {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(GitPullResponse {
            success: dto.success,
            message: dto.message,
            files_changed: dto.files_changed as i32,
            commit_hash: dto.commit_hash,
            conflicts: if has_conflicts { Some(conflicts) } else { None },
            git_status: None,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/git/pull/start",
    tag = "Git",
    responses(
        (status = 200, body = GitPullSessionResponse),
        (status = 400, body = GitPullSessionResponse),
        (status = 409, body = GitPullSessionResponse, description = "Conflicts detected")
    )
)]
pub async fn start_pull_session(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<GitPullSessionResponse>), StatusCode> {
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

    let service = ctx.git_service();
    let session = match service.start_pull_session_flow(workspace_id, user_id).await {
        Ok(v) => v,
        Err(err) => {
            let message = match &err {
                ServiceError::BadRequest("workspace_has_pending_changes") => {
                    "Workspace has pending changes. Commit, sync, or discard them before pulling."
                        .to_string()
                }
                other => other.to_string(),
            };
            let status = map_git_error(err);
            return Ok((
                status,
                Json(GitPullSessionResponse {
                    session_id: Uuid::nil(),
                    status: "error".to_string(),
                    conflicts: Vec::new(),
                    resolutions: Vec::new(),
                    message: Some(message),
                }),
            ));
        }
    };
    if session.status == "error" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(GitPullSessionResponse {
                session_id: session.id,
                status: session.status,
                conflicts: Vec::new(),
                resolutions: Vec::new(),
                message: session.message,
            }),
        ));
    }
    let conflicts = session
        .conflicts
        .clone()
        .into_iter()
        .map(Into::into)
        .collect::<Vec<GitPullConflictItem>>();
    let has_conflicts = !conflicts.is_empty();
    let status = if has_conflicts {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(GitPullSessionResponse {
            session_id: session.id,
            status: session.status,
            conflicts,
            resolutions: Vec::new(),
            message: session.message,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/git/pull/session/{id}",
    tag = "Git",
    responses((status = 200, body = GitPullSessionResponse))
)]
pub async fn get_pull_session(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<GitPullSessionResponse>, StatusCode> {
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

    let service = ctx.git_service();
    let state = service
        .load_pull_session_with_stale_check(workspace_id, id)
        .await
        .map_err(map_git_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(GitPullSessionResponse {
        session_id: state.id,
        status: state.status,
        conflicts: state.conflicts.into_iter().map(Into::into).collect(),
        resolutions: state
            .resolutions
            .into_iter()
            .map(|r| GitPullResolution {
                path: r.path,
                choice: r.choice,
                content: r.content,
            })
            .collect(),
        message: state.message,
    }))
}

#[utoipa::path(
    post,
    path = "/api/git/pull/session/{id}/resolve",
    tag = "Git",
    request_body = GitPullRequest,
    responses(
        (status = 200, body = GitPullSessionResponse),
        (status = 400, body = GitPullSessionResponse),
        (status = 409, body = GitPullSessionResponse)
    )
)]
pub async fn resolve_pull_session(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(req): Json<GitPullRequest>,
) -> Result<(StatusCode, Json<GitPullSessionResponse>), StatusCode> {
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

    let service = ctx.git_service();
    let existing_session = service
        .load_pull_session_with_stale_check(workspace_id, id)
        .await
        .map_err(map_git_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let resolutions = req.resolutions.unwrap_or_default();
    let session = match service
        .resolve_pull_session_flow(
            workspace_id,
            user_id,
            id,
            resolutions
                .iter()
                .cloned()
                .map(|r| GitPullResolutionDto {
                    path: r.path,
                    choice: r.choice,
                    content: r.content,
                })
                .collect(),
        )
        .await
    {
        Ok(v) => v,
        Err(err) => {
            let message = match &err {
                ServiceError::BadRequest("workspace_has_pending_changes") => {
                    "Workspace has pending changes. Commit, sync, or discard them before pulling."
                        .to_string()
                }
                other => other.to_string(),
            };
            let status = map_git_error(err);
            return Ok((
                status,
                Json(GitPullSessionResponse {
                    session_id: id,
                    status: "error".to_string(),
                    conflicts: existing_session
                        .conflicts
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    resolutions: existing_session
                        .resolutions
                        .into_iter()
                        .map(|r| GitPullResolution {
                            path: r.path,
                            choice: r.choice,
                            content: r.content,
                        })
                        .collect(),
                    message: Some(message),
                }),
            ));
        }
    };

    let mut status_code = StatusCode::OK;

    let conflicts: Vec<GitPullConflictItem> = session
        .conflicts
        .clone()
        .into_iter()
        .map(Into::into)
        .collect();
    if !conflicts.is_empty() {
        status_code = StatusCode::CONFLICT;
    }
    if session.status == "stale" {
        status_code = StatusCode::CONFLICT;
    }
    if session.status == "error" {
        status_code = StatusCode::BAD_REQUEST;
    }
    let session_status = session.status.clone();

    Ok((
        status_code,
        Json(GitPullSessionResponse {
            session_id: id,
            status: session_status.clone(),
            conflicts,
            resolutions,
            message: if session_status == "error" {
                session.message
            } else if status_code == StatusCode::CONFLICT && session_status == "stale" {
                Some("Pull session is stale. Please start a new pull.".to_string())
            } else {
                session.message
            },
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/git/pull/session/{id}/finalize",
    tag = "Git",
    responses(
        (status = 200, body = GitPullResponse),
        (status = 400, body = GitPullResponse),
        (status = 409, body = GitPullResponse)
    )
)]
pub async fn finalize_pull_session(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<(StatusCode, Json<GitPullResponse>), StatusCode> {
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

    let service = ctx.git_service();
    let FinalizePullSessionResult {
        session,
        git_status,
    } = service
        .finalize_pull_session_flow(workspace_id, id)
        .await
        .map_err(map_git_error)?;
    if session.status == "error" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(GitPullResponse {
                success: false,
                message: session
                    .message
                    .clone()
                    .unwrap_or_else(|| "pull failed".to_string()),
                files_changed: 0,
                commit_hash: None,
                conflicts: Some(session.conflicts.into_iter().map(Into::into).collect()),
                git_status: None,
            }),
        ));
    }
    if session.status == "stale" {
        return Ok((
            StatusCode::CONFLICT,
            Json(GitPullResponse {
                success: false,
                message: session
                    .message
                    .clone()
                    .unwrap_or_else(|| "pull session stale".to_string()),
                files_changed: 0,
                commit_hash: None,
                conflicts: Some(session.conflicts.into_iter().map(Into::into).collect()),
                git_status: None,
            }),
        ));
    }
    if !session.conflicts.is_empty() {
        return Ok((
            StatusCode::CONFLICT,
            Json(GitPullResponse {
                success: false,
                message: "conflicts remaining".to_string(),
                files_changed: 0,
                commit_hash: None,
                conflicts: Some(session.conflicts.into_iter().map(Into::into).collect()),
                git_status: None,
            }),
        ));
    }
    Ok((
        StatusCode::OK,
        Json(GitPullResponse {
            success: true,
            message: session
                .message
                .clone()
                .unwrap_or_else(|| "merge completed".to_string()),
            files_changed: 0,
            commit_hash: None,
            conflicts: None,
            git_status: git_status.map(Into::into),
        }),
    ))
}
