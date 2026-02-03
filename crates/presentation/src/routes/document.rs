//! Document routes

use application::document::{
    ArchiveDocumentCommand, ArchiveDocumentHandler, CreateDocumentCommand, CreateDocumentHandler,
    CreateDocumentUpdateCommand, CreateDocumentUpdateHandler, DeleteDocumentCommand,
    DeleteDocumentHandler, GetDocumentHandler, GetDocumentQuery, ListDocumentUpdatesHandler,
    ListDocumentUpdatesQuery, ListDocumentsHandler, ListDocumentsQuery, UnarchiveDocumentCommand,
    UnarchiveDocumentHandler, UpdateDocumentCommand, UpdateDocumentHandler,
};
use application::domain::document::{DocumentId, DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DocumentEncryptedKeyRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;

/// Create document routes under /api/workspaces/{workspace_id}/documents
///
/// Only for listing and creating documents (require workspace context).
pub fn workspace_routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>()
-> Router<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    Router::new().route(
        "/",
        get(list_documents::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>)
            .post(create_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>),
    )
}

/// Create document routes under /api/documents
///
/// For single document access by document ID only.
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    Router::new()
        .route(
            "/{document_id}",
            get(get_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>)
                .patch(update_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>)
                .delete(delete_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>),
        )
        .route(
            "/{document_id}/archive",
            post(archive_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>),
        )
        .route(
            "/{document_id}/unarchive",
            post(unarchive_document::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>),
        )
        .route(
            "/{document_id}/updates",
            get(list_updates::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>)
                .post(create_update::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>),
        )
        .with_state(state)
}

/// Document response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentResponse {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_title: Option<String>,
    pub slug: String,
    pub doc_type: String,
    pub is_encrypted: bool,
    pub is_archived: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
}

/// Create document request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentRequest {
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
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub root_only: bool,
    #[serde(default)]
    pub include_archived: bool,
}

/// Document error response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentErrorResponse {
    pub error: String,
}

/// List documents response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDocumentsResponse {
    pub documents: Vec<DocumentResponse>,
}

/// Document update response (single update)
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentUpdateResponse {
    pub seq: i64,
    /// Base64url-encoded encrypted Yjs update binary
    pub update_data: String,
    /// Base64url-encoded 24-byte nonce
    pub nonce: String,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// List document updates response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDocumentUpdatesResponse {
    pub updates: Vec<DocumentUpdateResponse>,
}

/// List document updates query params
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListDocumentUpdatesParams {
    /// If provided, only return updates after this sequence number
    pub after_seq: Option<i64>,
}

/// Create document update request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentUpdateRequest {
    /// Base64url-encoded encrypted Yjs update binary
    pub update_data: String,
    /// Base64url-encoded 24-byte nonce
    pub nonce: String,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// Create document update response
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateDocumentUpdateResponse {
    pub seq: i64,
}

// Helper to convert Document to DocumentResponse
fn document_to_response(doc: application::domain::document::Document) -> DocumentResponse {
    // Compute is_archived before moving fields out of doc
    let is_archived = doc.is_archived();

    DocumentResponse {
        id: doc.id.to_string(),
        workspace_id: doc.workspace_id.to_string(),
        parent_id: doc.parent_id.map(|id| id.to_string()),
        title: doc.title,
        encrypted_title: doc.encrypted_title.map(|v| base64_url::encode(&v)),
        slug: doc.slug,
        doc_type: doc.doc_type.as_str().to_string(),
        is_encrypted: doc.is_encrypted,
        is_archived,
        created_by: doc.created_by.map(|id| id.to_string()),
        created_at: doc.created_at.to_rfc3339(),
        updated_at: doc.updated_at.to_rfc3339(),
        archived_at: doc.archived_at.map(|dt| dt.to_rfc3339()),
    }
}

/// List documents in a workspace
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}/documents",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
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
pub async fn list_documents<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(workspace_id): Path<Uuid>,
    Query(params): Query<ListDocumentsParams>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    // Determine parent_id filter
    let parent_id = if params.root_only {
        Some(None) // Root documents only
    } else {
        params.parent_id.map(|id| Some(DocumentId::from_uuid(id)))
    };

    let handler = ListDocumentsHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = ListDocumentsQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: user.id,
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
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Create a new document
#[utoipa::path(
    post,
    path = "/api/workspaces/{workspace_id}/documents",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
    ),
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
pub async fn create_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(workspace_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateDocumentRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    // Decode encrypted title if provided
    let encrypted_title = request
        .encrypted_title
        .map(|s| base64_url::decode(&s))
        .transpose()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid encrypted_title encoding".to_string(),
                }),
            )
        });

    let encrypted_title = match encrypted_title {
        Ok(et) => et,
        Err(response) => return response.into_response(),
    };

    let encrypted_title_nonce = request
        .encrypted_title_nonce
        .map(|s| base64_url::decode(&s))
        .transpose()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid encrypted_title_nonce encoding".to_string(),
                }),
            )
        });

    let encrypted_title_nonce = match encrypted_title_nonce {
        Ok(etn) => etn,
        Err(response) => return response.into_response(),
    };

    let handler = CreateDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = CreateDocumentCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: user.id,
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
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_conflict() {
                StatusCode::CONFLICT
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn get_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = GetDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = GetDocumentQuery {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
    };

    match handler.handle(query).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn update_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<UpdateDocumentRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    // Decode encrypted title if provided
    let encrypted_title = request
        .encrypted_title
        .map(|s| base64_url::decode(&s))
        .transpose()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid encrypted_title encoding".to_string(),
                }),
            )
        });

    let encrypted_title = match encrypted_title {
        Ok(et) => et,
        Err(response) => return response.into_response(),
    };

    let encrypted_title_nonce = request
        .encrypted_title_nonce
        .map(|s| base64_url::decode(&s))
        .transpose()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid encrypted_title_nonce encoding".to_string(),
                }),
            )
        });

    let encrypted_title_nonce = match encrypted_title_nonce {
        Ok(etn) => etn,
        Err(response) => return response.into_response(),
    };

    let handler = UpdateDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = UpdateDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
        title: request.title,
        encrypted_title,
        encrypted_title_nonce,
        parent_id: request.parent_id.map(|opt| opt.map(DocumentId::from_uuid)),
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_conflict() {
                StatusCode::CONFLICT
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn delete_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = DeleteDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = DeleteDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn archive_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = ArchiveDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = ArchiveDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_conflict() {
                StatusCode::CONFLICT
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn unarchive_document<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = UnarchiveDocumentHandler::new(
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = UnarchiveDocumentCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(document_to_response(result.document))).into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("document operation internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Authenticated user info (minimal)
struct AuthenticatedUser {
    id: application::domain::identity::UserId,
}

/// Authenticate user from session cookie
async fn authenticate_user<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    state: &AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>,
    headers: &axum::http::HeaderMap,
) -> Result<AuthenticatedUser, axum::response::Response>
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Extract session token from cookie
    let token = match crate::auth::extract_session_token(headers) {
        Ok(t) => t,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(DocumentErrorResponse { error: e.error }),
            )
                .into_response());
        }
    };

    // Hash the token
    let token_hash = crate::auth::hash_session_token(token);

    // Validate session
    let session_repo = state.session_repo();
    let session = match session_repo.find_by_token_hash(&token_hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(DocumentErrorResponse {
                    error: "invalid session".to_string(),
                }),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!("Failed to find session: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DocumentErrorResponse {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response());
        }
    };

    // Check if session is expired
    if session.is_expired() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(DocumentErrorResponse {
                error: "session expired".to_string(),
            }),
        )
            .into_response());
    }

    Ok(AuthenticatedUser {
        id: session.user_id,
    })
}

/// List document updates (CRDT update log)
#[utoipa::path(
    get,
    path = "/api/documents/{document_id}/updates",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
        ("after_seq" = Option<i64>, Query, description = "Only return updates after this sequence number"),
    ),
    responses(
        (status = 200, description = "List of encrypted document updates", body = ListDocumentUpdatesResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn list_updates<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    Query(params): Query<ListDocumentUpdatesParams>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = ListDocumentUpdatesHandler::new(
        state.document_repo(),
        state.document_update_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = ListDocumentUpdatesQuery {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
        after_seq: params.after_seq,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let updates = result
                .updates
                .into_iter()
                .map(|u| DocumentUpdateResponse {
                    seq: u.seq,
                    update_data: base64_url::encode(&u.update_data),
                    nonce: base64_url::encode(&u.nonce),
                    key_version: u.key_version,
                    timestamp: u.timestamp,
                })
                .collect();
            (StatusCode::OK, Json(ListDocumentUpdatesResponse { updates })).into_response()
        }
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else {
                tracing::error!("document update list internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Create a new document update (CRDT update)
#[utoipa::path(
    post,
    path = "/api/documents/{document_id}/updates",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    request_body = CreateDocumentUpdateRequest,
    responses(
        (status = 201, description = "Document update created", body = CreateDocumentUpdateResponse),
        (status = 400, description = "Bad request (invalid nonce, encoding)", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
        (status = 409, description = "Document is archived", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn create_update<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS>>,
    Path(document_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateDocumentUpdateRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    // Decode update_data
    let update_data = match base64_url::decode(&request.update_data) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid update_data encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Decode nonce
    let nonce = match base64_url::decode(&request.nonce) {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DocumentErrorResponse {
                    error: "invalid nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = CreateDocumentUpdateHandler::new(
        state.document_repo(),
        state.document_update_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = CreateDocumentUpdateCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: user.id,
        update_data,
        nonce,
        key_version: request.key_version,
        timestamp: request.timestamp,
    };

    match handler.handle(command).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(CreateDocumentUpdateResponse { seq: result.seq }),
        )
            .into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_conflict() {
                StatusCode::CONFLICT
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                tracing::error!("document update create internal error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(DocumentErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                status,
                Json(DocumentErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}
