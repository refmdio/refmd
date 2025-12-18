use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::context::AppContext;
use crate::http::identity::auth::Bearer;
use application::plugins::use_cases::install_from_url::InstallPluginError;
use domain::access::permissions::{PERM_PLUGIN_INSTALL, PERM_PLUGIN_UNINSTALL};

use super::types::{InstallFromUrlBody, InstallResponse, UninstallBody, ensure_valid_plugin_id};
use super::util::{map_plugin_service_error, resolve_plugin_user_context};

#[utoipa::path(
    post,
    path = "/api/me/plugins/install-from-url",
    request_body = InstallFromUrlBody,
    responses((status = 200, body = InstallResponse)),
    tag = "Plugins",
    operation_id = "pluginsInstallFromUrl"
)]
pub async fn install_from_url(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(body): Json<InstallFromUrlBody>,
) -> Result<Json<InstallResponse>, StatusCode> {
    let bearer_token_raw = bearer.0;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        Some(PERM_PLUGIN_INSTALL),
    )
    .await?;

    let management = ctx.plugin_management();

    match management
        .install_from_url(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            &body.url,
            body.token.as_deref(),
        )
        .await
    {
        Ok(installed) => Ok(Json(InstallResponse {
            id: installed.id,
            version: installed.version,
        })),
        Err(err) => {
            tracing::error!(error = ?err, "failed to install plugin from url");
            match err {
                InstallPluginError::Download(_) => Err(StatusCode::BAD_GATEWAY),
                InstallPluginError::Install(inner) => match inner {
                    application::plugins::ports::plugin_installer::PluginInstallError::InvalidPackage(_) => {
                        Err(StatusCode::BAD_REQUEST)
                    }
                    application::plugins::ports::plugin_installer::PluginInstallError::Storage(_) => {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                },
                InstallPluginError::Persist(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                InstallPluginError::Event(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/me/plugins/uninstall",
    request_body = UninstallBody,
    responses((status = 204)),
    tag = "Plugins",
    operation_id = "pluginsUninstall"
)]
pub async fn uninstall(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(body): Json<UninstallBody>,
) -> Result<StatusCode, StatusCode> {
    let bearer_token_raw = bearer.0;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        Some(PERM_PLUGIN_UNINSTALL),
    )
    .await?;
    let UninstallBody { id } = body;
    let trimmed_id = id.trim();
    ensure_valid_plugin_id(trimmed_id)?;
    ctx.plugin_management()
        .uninstall(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            trimmed_id,
        )
        .await
        .map_err(map_plugin_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
