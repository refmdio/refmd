use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use crate::context::GitContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;
use application::git::dtos::{GitPullRequestDto, GitPullResolutionDto};
use application::git::services::FinalizePullSessionResult;
use domain::access::permissions::PERM_GIT_SYNC;
use domain::git::pull_session::GitPullSessionStatus;

use super::types::{
    GitPullConflictItem, GitPullRequest, GitPullResolution, GitPullResponse,
    GitPullSessionResponse, map_git_error,
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
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    Json(req): Json<GitPullRequest>,
) -> Result<(StatusCode, Json<GitPullResponse>), ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;
    let service = ctx.git_service();
    let dto = service
        .pull_repository(
            auth.workspace_id,
            auth.user_id,
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
            let status = map_git_error(err).status();
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
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
) -> Result<(StatusCode, Json<GitPullSessionResponse>), ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;

    let service = ctx.git_service();
    let session = match service
        .start_pull_session_flow(auth.workspace_id, auth.user_id)
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
            let status = map_git_error(err).status();
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
    if session.status == GitPullSessionStatus::Error {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(GitPullSessionResponse {
                session_id: session.id,
                status: session.status.as_str().to_string(),
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
            status: session.status.as_str().to_string(),
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
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<GitPullSessionResponse>, ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;

    let service = ctx.git_service();
    let state = service
        .load_pull_session_with_stale_check(auth.workspace_id, id)
        .await
        .map_err(map_git_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    Ok(Json(GitPullSessionResponse {
        session_id: state.id,
        status: state.status.as_str().to_string(),
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
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(req): Json<GitPullRequest>,
) -> Result<(StatusCode, Json<GitPullSessionResponse>), ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;

    let service = ctx.git_service();
    let existing_session = service
        .load_pull_session_with_stale_check(auth.workspace_id, id)
        .await
        .map_err(map_git_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    let resolutions = req.resolutions.unwrap_or_default();
    let session = match service
        .resolve_pull_session_flow(
            auth.workspace_id,
            auth.user_id,
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
            let status = map_git_error(err).status();
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
    if session.status == GitPullSessionStatus::Stale {
        status_code = StatusCode::CONFLICT;
    }
    if session.status == GitPullSessionStatus::Error {
        status_code = StatusCode::BAD_REQUEST;
    }
    let session_status = session.status;

    Ok((
        status_code,
        Json(GitPullSessionResponse {
            session_id: id,
            status: session_status.as_str().to_string(),
            conflicts,
            resolutions,
            message: if session_status == GitPullSessionStatus::Error {
                session.message
            } else if status_code == StatusCode::CONFLICT
                && session_status == GitPullSessionStatus::Stale
            {
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
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<(StatusCode, Json<GitPullResponse>), ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;

    let service = ctx.git_service();
    let FinalizePullSessionResult {
        session,
        git_status,
    } = service
        .finalize_pull_session_flow(auth.workspace_id, id)
        .await
        .map_err(map_git_error)?;
    if session.status == GitPullSessionStatus::Error {
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
    if session.status == GitPullSessionStatus::Stale {
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
