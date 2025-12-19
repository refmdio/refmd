use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::context::AppContext;
#[allow(unused_imports)]
use crate::http::documents::DocumentDownloadBinary;
use crate::http::error::ApiError;
use crate::http::identity::auth::{
    self, apply_session_cookies, extract_client_ip, extract_refresh_token, extract_user_agent,
};
use crate::security::token as security_token;
use crate::security::token::Bearer;
use application::core::services::access;
use application::core::services::errors::ServiceError;
use application::identity::services::auth::user_sessions::SessionMetadata;
use application::workspaces::ports::workspace_repository::WorkspaceListItem;
use domain::access::permissions::{PERM_DOC_VIEW, PERM_WORKSPACE_DELETE, PERM_WORKSPACE_UPDATE};
use domain::workspaces::roles::{WorkspaceRoleKind, WorkspaceSystemRole};

use super::types::{
    CreateWorkspaceRequest, DownloadWorkspaceQuery, SwitchWorkspaceResponse,
    UpdateWorkspaceRequest, WorkspaceResponse, map_service_error, require_permission, to_response,
};

#[utoipa::path(get, path = "/api/workspaces", tag = "Workspaces", responses((status = 200, body = [WorkspaceResponse])))]
pub async fn list_workspaces(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<Vec<WorkspaceResponse>>, ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    let items = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(to_response)
        .collect();
    Ok(Json(items))
}

#[utoipa::path(post, path = "/api/workspaces", tag = "Workspaces", request_body = CreateWorkspaceRequest, responses((status = 200, body = WorkspaceResponse)))]
pub async fn create_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(payload): Json<CreateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    if payload.name.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_workspace_name"));
    }
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    let workspace = ctx
        .workspace_service()
        .create_workspace(
            user_id,
            payload.name.trim(),
            payload.icon.as_deref(),
            payload.description.as_deref(),
        )
        .await
        .map_err(map_service_error)?;
    let memberships = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let created = memberships
        .into_iter()
        .find(|item| item.id == workspace.id)
        .unwrap_or(WorkspaceListItem {
            id: workspace.id,
            name: workspace.name,
            slug: workspace.slug,
            icon: workspace.icon,
            description: workspace.description,
            is_personal: workspace.is_personal,
            role_kind: WorkspaceRoleKind::System,
            system_role: Some(WorkspaceSystemRole::Owner),
            custom_role_id: None,
            is_default: false,
        });
    Ok(Json(to_response(created)))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = WorkspaceResponse))
)]
pub async fn get_workspace_detail(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    let workspaces = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let workspace = workspaces
        .into_iter()
        .find(|ws| ws.id == id)
        .ok_or(ApiError::not_found("workspace_not_found"))?;
    Ok(Json(to_response(workspace)))
}

#[utoipa::path(
    put,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = UpdateWorkspaceRequest,
    responses((status = 200, body = WorkspaceResponse))
)]
pub async fn update_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    if let Some(name) = payload.name.as_deref() {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("invalid_workspace_name"));
        }
    }
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    require_permission(&ctx, id, user_id, PERM_WORKSPACE_UPDATE).await?;
    let normalized_name = payload
        .name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let normalized_icon = payload
        .icon
        .as_ref()
        .map(|value| value.trim())
        .map(|value| value.to_string());
    let normalized_description = payload
        .description
        .as_ref()
        .map(|value| value.trim())
        .map(|value| value.to_string());
    let updated = ctx
        .workspace_service()
        .update_workspace(
            id,
            normalized_name.as_deref(),
            normalized_icon.as_deref(),
            normalized_description.as_deref(),
        )
        .await
        .map_err(map_service_error)?
        .ok_or(ApiError::not_found("workspace_not_found"))?;

    let memberships = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let mut membership = memberships
        .into_iter()
        .find(|ws| ws.id == id)
        .ok_or(ApiError::forbidden("forbidden"))?;
    membership.name = updated.name;
    membership.icon = updated.icon;
    membership.description = updated.description;
    membership.slug = updated.slug;
    Ok(Json(to_response(membership)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 204))
)]
pub async fn delete_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    require_permission(&ctx, id, user_id, PERM_WORKSPACE_DELETE).await?;
    let workspace = ctx
        .workspace_service()
        .get_workspace(id)
        .await
        .map_err(map_service_error)?
        .ok_or(ApiError::not_found("workspace_not_found"))?;
    if workspace.is_personal {
        return Err(ApiError::bad_request("cannot_delete_personal_workspace"));
    }
    let members = ctx
        .workspace_service()
        .list_members(id)
        .await
        .map_err(map_service_error)?;
    if members.iter().any(|member| member.is_default) {
        return Err(ApiError::conflict("workspace_has_default_member"));
    }
    ctx.workspace_service()
        .delete_workspace(id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/leave",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 204))
)]
pub async fn leave_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(workspace_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    ctx.workspace_service()
        .leave_workspace(workspace_id, user_id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/switch",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = SwitchWorkspaceResponse))
)]
pub async fn switch_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<SwitchWorkspaceResponse>), ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;
    ctx.workspace_service()
        .set_default_workspace(user_id, id)
        .await
        .map_err(map_service_error)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let session_service = ctx.session_service();
    let mut issued = None;
    if let Some(refresh_token) = extract_refresh_token(&headers) {
        match session_service
            .refresh_session(
                &refresh_token,
                Some(id),
                SessionMetadata {
                    user_agent,
                    ip_address: client_ip.as_deref(),
                },
            )
            .await
        {
            Ok(bundle) => issued = Some(bundle),
            Err(ServiceError::Unauthorized | ServiceError::TokenExpired) => {
                issued = None;
            }
            Err(err) => return Err(auth::map_auth_error(err)),
        }
    }
    let issued = match issued {
        Some(bundle) => bundle,
        None => session_service
            .issue_new_session(
                user_id,
                id,
                false,
                SessionMetadata {
                    user_agent,
                    ip_address: client_ip.as_deref(),
                },
            )
            .await
            .map_err(auth::map_auth_error)?,
    };
    let mut response_headers = HeaderMap::new();
    apply_session_cookies(&ctx, &mut response_headers, &issued);
    Ok((
        response_headers,
        Json(SwitchWorkspaceResponse {
            access_token: issued.access.token,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/download",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("format" = Option<DownloadFormat>, Query, description = "Download format (archive only)")
    ),
    responses(
        (status = 200, description = "Workspace download", body = DocumentDownloadBinary, content_type = "application/octet-stream"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workspace not found")
    )
)]
pub async fn download_workspace_archive(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Query(params): Query<DownloadWorkspaceQuery>,
) -> Result<Response, ApiError> {
    let user_id = security_token::require_user_id(&ctx, bearer)
        .await
        .map_err(security_token::map_actor_error)?;

    require_permission(&ctx, id, user_id, PERM_DOC_VIEW)
        .await?;

    let workspace = ctx
        .workspace_service()
        .get_workspace(id)
        .await
        .map_err(map_service_error)?
        .ok_or(ApiError::not_found("workspace_not_found"))?;

    let actor = access::Actor::User(user_id);
    let download = ctx
        .document_service()
        .download_workspace_root(&actor, id, &workspace.name, params.format.into())
        .await
        .map_err(|err| match err {
            ServiceError::Unauthorized | ServiceError::TokenExpired | ServiceError::Forbidden => {
                ApiError::forbidden("forbidden")
            }
            ServiceError::Conflict | ServiceError::NotFound => ApiError::not_found("not_found"),
            ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
            ServiceError::Unexpected(inner) => {
                tracing::error!(error = ?inner, workspace_id = %id, "workspace_download_failed");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        })?;

    let mut headers = HeaderMap::new();
    let content_type = HeaderValue::from_str(&download.content_type)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid_header"))?;
    headers.insert(axum::http::header::CONTENT_TYPE, content_type);
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition = HeaderValue::from_str(&disposition)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid_header"))?;
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}
