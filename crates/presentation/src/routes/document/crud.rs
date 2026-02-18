//! Document CRUD routes: list, create, get, update, delete, archive, unarchive

use application::document::{
    ArchiveDocumentCommand, ArchiveDocumentHandler, CreateDocumentCommand, CreateDocumentHandler,
    DeleteDocumentCommand, DeleteDocumentHandler, GetDocumentHandler, GetDocumentQuery,
    ListDocumentsHandler, ListDocumentsQuery, UnarchiveDocumentCommand, UnarchiveDocumentHandler,
    UpdateDocumentCommand, UpdateDocumentHandler,
};
use application::types::{DocumentId, WorkspaceId};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::DocumentSubState;
use crate::auth::PopVerifiedUser;
use crate::routes::app_error_response;
use super::{DocumentErrorResponse, DocumentResponse, decode_encrypted_title_fields, document_to_response};

/// Create document request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentRequest {
    pub workspace_id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_title_nonce: Option<String>,
    #[serde(default)]
    pub is_folder: bool,
}

/// Update document request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocumentRequest {
    pub title: Option<String>,
    pub parent_id: Option<Option<Uuid>>,
    pub encrypted_title: Option<String>,
    pub encrypted_title_nonce: Option<String>,
}

/// List documents query params
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListDocumentsParams {
    pub workspace_id: Uuid,
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub root_only: bool,
    #[serde(default)]
    pub include_archived: bool,
}

/// List documents response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDocumentsResponse {
    pub documents: Vec<DocumentResponse>,
}

/// List documents in a workspace
#[utoipa::path(
    get,
    path = "/api/documents",
    params(
        ("workspace_id" = Uuid, Query, description = "Workspace ID"),
        ("parent_id" = Option<Uuid>, Query, description = "Filter by parent ID"),
        ("root_only" = bool, Query, description = "Only return root documents"),
        ("include_archived" = bool, Query, description = "Include archived documents"),
    ),
    responses(
        (status = 200, description = "List of documents", body = ListDocumentsResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Not a member of this workspace", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn list_documents(
    State(state): State<DocumentSubState>,
    Query(params): Query<ListDocumentsParams>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    // Determine parent_id filter
    let parent_id = if params.root_only {
        Some(None) // Root documents only
    } else {
        params.parent_id.map(|id| Some(DocumentId::from_uuid(id)))
    };

    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = ListDocumentsHandler::new(doc_repo, member_repo, role_repo);

    let query = ListDocumentsQuery {
        workspace_id: WorkspaceId::from_uuid(params.workspace_id),
        user_id: pop_user.user_id,
        parent_id,
        include_archived: params.include_archived,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let documents = result
                .documents
                .into_iter()
                .map(document_to_response)
                .collect();
            (StatusCode::OK, Json(ListDocumentsResponse { documents })).into_response()
        }
        Err(e) => app_error_response!(e, DocumentErrorResponse, not_found, forbidden),
    }
}

/// Create a new document
#[utoipa::path(
    post,
    path = "/api/documents",
    request_body = CreateDocumentRequest,
    responses(
        (status = 201, description = "Document created", body = DocumentResponse),
        (status = 400, description = "Bad request", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 409, description = "Slug conflict", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn create_document(
    State(state): State<DocumentSubState>,
    pop_user: PopVerifiedUser,
    Json(request): Json<CreateDocumentRequest>,
) -> impl IntoResponse {
    // Decode encrypted title fields
    let (encrypted_title, encrypted_title_nonce) =
        match decode_encrypted_title_fields(request.encrypted_title, request.encrypted_title_nonce)
        {
            Ok(fields) => fields,
            Err(response) => return response.into_response(),
        };

    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = CreateDocumentHandler::new(doc_repo, member_repo, role_repo);

    let command = CreateDocumentCommand {
        workspace_id: WorkspaceId::from_uuid(request.workspace_id),
        user_id: pop_user.user_id,
        title: request.title,
        parent_id: request.parent_id.map(DocumentId::from_uuid),
        encrypted_title,
        encrypted_title_nonce,
        is_folder: request.is_folder,
    };

    match handler.handle(command).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(document_to_response(result.document)),
        )
            .into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, conflict, bad_request, not_found, forbidden),
    }
}

/// Get a document
#[utoipa::path(
    get,
    path = "/api/documents/{document_id}",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    responses(
        (status = 200, description = "Document details", body = DocumentResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn get_document(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = GetDocumentHandler::new(doc_repo, member_repo, role_repo);

    let query = GetDocumentQuery {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, not_found, forbidden),
    }
}

/// Update a document
#[utoipa::path(
    patch,
    path = "/api/documents/{document_id}",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    request_body = UpdateDocumentRequest,
    responses(
        (status = 200, description = "Document updated", body = DocumentResponse),
        (status = 400, description = "Bad request", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn update_document(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
    Json(request): Json<UpdateDocumentRequest>,
) -> impl IntoResponse {
    // Decode encrypted title fields
    let (encrypted_title, encrypted_title_nonce) =
        match decode_encrypted_title_fields(request.encrypted_title, request.encrypted_title_nonce)
        {
            Ok(fields) => fields,
            Err(response) => return response.into_response(),
        };

    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = UpdateDocumentHandler::new(doc_repo, member_repo, role_repo);

    let command = UpdateDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
        title: request.title,
        encrypted_title,
        encrypted_title_nonce,
        parent_id: request.parent_id.map(|opt| opt.map(DocumentId::from_uuid)),
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, conflict, bad_request, not_found, forbidden),
    }
}

/// Delete a document (permanent)
#[utoipa::path(
    delete,
    path = "/api/documents/{document_id}",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    responses(
        (status = 204, description = "Document deleted"),
        (status = 400, description = "Folder not empty", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn delete_document(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = DeleteDocumentHandler::new(doc_repo, member_repo, role_repo);

    let command = DeleteDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Archive a document (read-only)
#[utoipa::path(
    post,
    path = "/api/documents/{document_id}/archive",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    responses(
        (status = 200, description = "Document archived", body = DocumentResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
        (status = 409, description = "Already archived", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn archive_document(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = ArchiveDocumentHandler::new(doc_repo, member_repo, role_repo);

    let command = ArchiveDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, conflict, not_found, forbidden),
    }
}

/// Unarchive a document
#[utoipa::path(
    post,
    path = "/api/documents/{document_id}/unarchive",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    responses(
        (status = 200, description = "Document unarchived", body = DocumentResponse),
        (status = 400, description = "Document not archived", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn unarchive_document(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let (doc_repo, member_repo, role_repo) = state.doc_member_role_repos();
    let handler = UnarchiveDocumentHandler::new(doc_repo, member_repo, role_repo);

    let command = UnarchiveDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, bad_request, not_found, forbidden),
    }
}
