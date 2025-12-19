use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::error::ApiError;
use application::plugins::services::management::{AssetRequestScope, PluginAssetRequest};

use super::util::map_plugin_service_error;

#[utoipa::path(
    get,
    path = "/api/plugin-assets",
    params(("token" = Option<String>, Query, description = "Share token (optional)")),
    responses((status = 200, description = "Plugin asset")),
    tag = "Plugins",
    operation_id = "pluginsGetAsset"
)]
pub async fn get_plugin_asset(
    State(ctx): State<AppContext>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let scope_raw = params
        .get("scope")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_scope"))?;
    let plugin_id = params
        .get("plugin")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_plugin"))?;
    let version = params
        .get("version")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_version"))?;
    let path = params
        .get("path")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_path"))?;
    let exp = params
        .get("exp")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_exp"))?;
    let expires_at = exp
        .parse::<i64>()
        .map_err(|_| ApiError::bad_request("invalid_exp"))?;
    let sig = params
        .get("sig")
        .map(|s| s.as_str())
        .ok_or(ApiError::bad_request("missing_sig"))?;
    let share_owned = params
        .get("share")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let scope = match scope_raw {
        "global" => AssetRequestScope::Global,
        "user" => {
            let owner_str = params
                .get("owner")
                .map(|s| s.as_str())
                .ok_or(ApiError::bad_request("missing_owner"))?;
            let owner_id = Uuid::parse_str(owner_str)
                .map_err(|_| ApiError::bad_request("invalid_owner"))?;
            AssetRequestScope::User {
                owner_id,
                share_token: share_owned.as_deref(),
            }
        }
        _ => return Err(ApiError::bad_request("invalid_scope")),
    };

    let payload = ctx
        .plugin_management()
        .fetch_asset(PluginAssetRequest {
            scope,
            plugin_id,
            version,
            path,
            expires_at,
            signature: sig,
        })
        .await
        .map_err(map_plugin_service_error)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&payload.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    Ok((headers, payload.bytes).into_response())
}
