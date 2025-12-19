use axum::http::HeaderMap;
use uuid::Uuid;

use crate::context::{HasAuthServices, HasWorkspaceService};
use crate::http::error::ApiError;
use crate::http::workspaces::map_service_error;
use application::domain::access::permissions::PermissionSet;

const WORKSPACE_HEADER: &str = "X-Workspace-ID";

pub async fn resolve_active_workspace_id(
    ctx: &(impl HasAuthServices + HasWorkspaceService),
    headers: &HeaderMap,
    bearer_token: Option<&str>,
    user_id: Uuid,
) -> Result<Uuid, ApiError> {
    let override_id = headers
        .get(WORKSPACE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|raw| raw.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            Uuid::parse_str(value).map_err(|_| ApiError::bad_request("invalid_workspace_id"))
        })
        .transpose()?;

    let workspaces = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;

    if workspaces.is_empty() {
        return Err(ApiError::forbidden("forbidden"));
    }

    if let Some(id) = override_id {
        let found = workspaces.iter().any(|ws| ws.id == id);
        if found {
            return Ok(id);
        }
        return Err(ApiError::forbidden("forbidden"));
    }

    if let Some(token) = bearer_token {
        let token_ws_id =
            if let Some(token_ws_id) = ctx.auth_service().workspace_from_token_claim(token) {
                Some(token_ws_id)
            } else {
                ctx.auth_service()
                    .workspace_from_token_async(token)
                    .await
                    .ok()
                    .flatten()
            };
        if let Some(token_ws_id) = token_ws_id
            && workspaces.iter().any(|ws| ws.id == token_ws_id)
        {
            return Ok(token_ws_id);
        }
    }

    if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
        return Ok(default_ws.id);
    }

    Ok(workspaces[0].id)
}

pub async fn ensure_workspace_permission(
    ctx: &(impl HasAuthServices + HasWorkspaceService),
    workspace_id: Uuid,
    user_id: Uuid,
    permission: &str,
) -> Result<(), ApiError> {
    let set = resolve_workspace_permissions(ctx, workspace_id, user_id).await?;
    if set.allows(permission) {
        Ok(())
    } else {
        Err(ApiError::forbidden("forbidden"))
    }
}

pub async fn resolve_workspace_permissions(
    ctx: &(impl HasAuthServices + HasWorkspaceService),
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<PermissionSet, ApiError> {
    ctx.workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(ApiError::forbidden("forbidden"))
}
