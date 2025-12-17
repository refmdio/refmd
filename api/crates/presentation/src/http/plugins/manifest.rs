use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::context::AppContext;
use crate::http::identity::auth::Bearer;

use super::types::ManifestItem;
use super::util::resolve_plugin_user_context;

#[utoipa::path(
    get,
    path = "/api/me/plugins/manifest",
    responses((status = 200, body = [ManifestItem])),
    tag = "Plugins",
    operation_id = "pluginsGetManifest"
)]
pub async fn get_manifest(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<ManifestItem>>, StatusCode> {
    let bearer_token = bearer.0;
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), None).await?;
    let manifests = ctx
        .plugin_management()
        .manifests_for_workspace(plugin_ctx.workspace_id, plugin_ctx.user_id)
        .await
        .map_err(super::util::map_plugin_service_error)?
        .into_iter()
        .map(ManifestItem::from)
        .collect();
    Ok(Json(manifests))
}
