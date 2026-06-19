use axum::{
    Json,
    extract::{Path, Query, State},
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::security::token::{self, Bearer};

use crate::http::documents::types::{
    CreateDocumentCommentReplyRequest, CreateDocumentCommentThreadRequest, DocumentCommentReply,
    DocumentCommentThread, DocumentCommentsResponse, SnapshotTokenQuery,
    UpdateDocumentCommentThreadRequest, map_service_error, to_http_comment_reply,
    to_http_comment_thread,
};

#[utoipa::path(
    get,
    path = "/api/documents/{id}/comments",
    tag = "Documents",
    operation_id = "listDocumentComments",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses((status = 200, body = DocumentCommentsResponse))
)]
pub async fn list_document_comments(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
) -> Result<Json<DocumentCommentsResponse>, ApiError> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, params.token.as_deref())
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();
    let threads = service
        .list_comments(&actor, id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(to_http_comment_thread)
        .collect();
    Ok(Json(DocumentCommentsResponse { threads }))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/comments",
    tag = "Documents",
    operation_id = "createDocumentCommentThread",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = CreateDocumentCommentThreadRequest,
    responses((status = 200, body = DocumentCommentThread))
)]
pub async fn create_document_comment_thread(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<CreateDocumentCommentThreadRequest>,
) -> Result<Json<DocumentCommentThread>, ApiError> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, params.token.as_deref())
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();
    let thread = service
        .create_comment_thread(
            &actor,
            id,
            body.id,
            body.marker,
            body.quote,
            body.body,
            body.start_line_number,
            body.start_column,
            body.end_line_number,
            body.end_column,
            body.start_offset,
            body.end_offset,
            body.tags,
            body.author_name,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_comment_thread(thread)))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/comments/{thread_id}/replies",
    tag = "Documents",
    operation_id = "createDocumentCommentReply",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("thread_id" = Uuid, Path, description = "Comment thread ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = CreateDocumentCommentReplyRequest,
    responses((status = 200, body = DocumentCommentReply))
)]
pub async fn create_document_comment_reply(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path((id, thread_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<CreateDocumentCommentReplyRequest>,
) -> Result<Json<DocumentCommentReply>, ApiError> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, params.token.as_deref())
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();
    let reply = service
        .add_comment_reply(&actor, id, thread_id, body.body, body.author_name)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_comment_reply(reply)))
}

#[utoipa::path(
    patch,
    path = "/api/documents/{id}/comments/{thread_id}",
    tag = "Documents",
    operation_id = "updateDocumentCommentThread",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("thread_id" = Uuid, Path, description = "Comment thread ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = UpdateDocumentCommentThreadRequest,
    responses((status = 200, body = DocumentCommentThread))
)]
pub async fn update_document_comment_thread(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path((id, thread_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<UpdateDocumentCommentThreadRequest>,
) -> Result<Json<DocumentCommentThread>, ApiError> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, params.token.as_deref())
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();
    let thread = service
        .update_comment_thread(
            &actor,
            id,
            thread_id,
            body.resolved,
            body.tags,
            body.anchored,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_comment_thread(thread)))
}
