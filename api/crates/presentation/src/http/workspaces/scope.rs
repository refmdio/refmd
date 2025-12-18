use axum::http::{HeaderMap, StatusCode};
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::workspaces::map_service_error;
use domain::access::permissions::PermissionSet;

const WORKSPACE_HEADER: &str = "X-Workspace-ID";

pub async fn resolve_active_workspace_id(
    ctx: &AppContext,
    headers: &HeaderMap,
    bearer_token: Option<&str>,
    user_id: Uuid,
) -> Result<Uuid, StatusCode> {
    let override_id = headers
        .get(WORKSPACE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|raw| raw.trim())
        .filter(|value| !value.is_empty())
        .map(|value| Uuid::parse_str(value).map_err(|_| StatusCode::BAD_REQUEST))
        .transpose()?;

    let workspaces = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;

    if workspaces.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(id) = override_id {
        let found = workspaces.iter().any(|ws| ws.id == id);
        if found {
            return Ok(id);
        }
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(token) = bearer_token {
        if let Some(token_ws_id) = ctx.auth_service().workspace_from_token_claim(token) {
            if workspaces.iter().any(|ws| ws.id == token_ws_id) {
                return Ok(token_ws_id);
            }
        } else if let Ok(Some(token_ws_id)) =
            ctx.auth_service().workspace_from_token_async(token).await
        {
            if workspaces.iter().any(|ws| ws.id == token_ws_id) {
                return Ok(token_ws_id);
            }
        }
    }

    if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
        return Ok(default_ws.id);
    }

    Ok(workspaces[0].id)
}

pub async fn ensure_workspace_permission(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
    permission: &str,
) -> Result<(), StatusCode> {
    let set = resolve_workspace_permissions(ctx, workspace_id, user_id).await?;
    if set.allows(permission) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub async fn resolve_workspace_permissions(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<PermissionSet, StatusCode> {
    ctx.workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::FORBIDDEN)
}
