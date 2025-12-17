use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::security::token::{self, Bearer};

#[allow(unused_imports)]
use crate::http::documents::types::{
    DocumentArchiveBinary, SnapshotDiffBaseParam, SnapshotDiffQuery, SnapshotDiffResponse,
    SnapshotListResponse, SnapshotRestoreResponse, SnapshotTokenQuery, map_service_error,
    snapshot_diff_side_response_from, snapshot_summary_from,
};

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of snapshots to return"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses((status = 200, body = SnapshotListResponse))
)]
pub async fn list_document_snapshots(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<crate::http::documents::types::ListSnapshotsQuery>>,
) -> Result<Json<SnapshotListResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let service = ctx.document_service();
    let records = service
        .list_snapshots(&actor, id, limit, offset)
        .await
        .map_err(map_service_error)?;
    let items = records.into_iter().map(snapshot_summary_from).collect();

    Ok(Json(SnapshotListResponse { items }))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/diff",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)"),
        ("compare" = Option<Uuid>, Query, description = "Snapshot ID to compare against (defaults to current document state)"),
        ("base" = Option<SnapshotDiffBaseParam>, Query, description = "Base comparison to use when compare is not provided (auto|current|previous)")
    ),
    responses((status = 200, body = SnapshotDiffResponse))
)]
pub async fn get_document_snapshot_diff(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotDiffQuery>>,
) -> Result<Json<SnapshotDiffResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let base_mode = params
        .base
        .map(SnapshotDiffBaseParam::into)
        .unwrap_or(SnapshotDiffBaseParam::Auto.into());

    let service = ctx.document_service();
    let result = service
        .snapshot_diff(&actor, id, snapshot_id, params.compare, base_mode)
        .await
        .map_err(map_service_error)?;

    let diff = result.diff;
    let base = snapshot_diff_side_response_from(result.base);
    let target = snapshot_diff_side_response_from(result.target);

    Ok(Json(SnapshotDiffResponse { base, target, diff }))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/restore",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses((status = 200, body = SnapshotRestoreResponse))
)]
pub async fn restore_document_snapshot(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
) -> Result<Json<SnapshotRestoreResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let service = ctx.document_service();
    let restored = service
        .restore_snapshot(&actor, id, snapshot_id)
        .await
        .map_err(map_service_error)?;

    Ok(Json(SnapshotRestoreResponse {
        snapshot: snapshot_summary_from(restored),
    }))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/download",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses(
        (status = 200, description = "Snapshot archive", body = DocumentArchiveBinary, content_type = "application/zip"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Snapshot not found")
    )
)]
pub async fn download_document_snapshot(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
) -> Result<Response, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let service = ctx.document_service();
    let download = service
        .download_snapshot(&actor, id, snapshot_id)
        .await
        .map_err(map_service_error)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition =
        HeaderValue::from_str(&disposition).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}
