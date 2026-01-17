use axum::{
    Json,
    extract::{Path, Query, State},
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::AuthedUser;
use crate::security::token::{self, Bearer};
use application::core::services::access;
use application::documents::services::DocumentPatchOperation;

use crate::http::documents::types::{
    Document, DocumentPatchOperationRequest, EncryptedUpdateEntry, GetContentResponse,
    PatchDocumentContentRequest, SnapshotTokenQuery, UpdateDocumentContentRequest,
    map_service_error, to_http_document,
};

#[utoipa::path(
    get,
    path = "/api/documents/{id}/content",
    tag = "Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = GetContentResponse))
)]
pub async fn get_document_content(
    State(ctx): State<DocumentsContext>,
    auth: AuthedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<GetContentResponse>, ApiError> {
    use base64::Engine;

    let actor = access::Actor::User(auth.user_id);
    let service = ctx.document_service();

    // Return Yjs snapshot bytes as Base64
    let content = service
        .get_content(&actor, id)
        .await
        .map_err(map_service_error)?;

    let updates = content.updates.map(|updates| {
        updates
            .into_iter()
            .map(|u| EncryptedUpdateEntry {
                seq: u.seq,
                data: base64::engine::general_purpose::STANDARD.encode(&u.data),
                nonce: u
                    .nonce
                    .map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
                signature: u
                    .signature
                    .map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
                public_key: u
                    .public_key
                    .map(|p| base64::engine::general_purpose::STANDARD.encode(&p)),
            })
            .collect()
    });

    Ok(Json(GetContentResponse {
        content: base64::engine::general_purpose::STANDARD.encode(&content.content),
        nonce: content
            .nonce
            .map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
        seq_at_snapshot: content.seq_at_snapshot,
        updates,
    }))
}

#[utoipa::path(
    put,
    path = "/api/documents/{id}/content",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = UpdateDocumentContentRequest,
    responses((status = 200, body = Document))
)]
pub async fn update_document_content(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<UpdateDocumentContentRequest>,
) -> Result<Json<Document>, ApiError> {
    use base64::Engine;

    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();

    // Check if this is an E2EE update (nonce provided)
    let updated = if body.nonce.is_some() {
        // E2EE mode: content is Base64 encoded encrypted Yjs state
        let content_bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.content)
            .map_err(|_| ApiError::bad_request("invalid_content_base64"))?;
        let nonce_bytes = body
            .nonce
            .as_ref()
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| ApiError::bad_request("invalid_nonce_base64"))
            })
            .transpose()?;
        let signature_bytes = body
            .signature
            .as_ref()
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| ApiError::bad_request("invalid_signature_base64"))
            })
            .transpose()?;

        service
            .update_content(&actor, id, &content_bytes, nonce_bytes.as_deref(), signature_bytes.as_deref())
            .await
            .map_err(map_service_error)?
    } else {
        // Plaintext mode: content is markdown
        service
            .update_content_from_markdown(&actor, id, &body.content)
            .await
            .map_err(map_service_error)?
    };

    Ok(Json(to_http_document(updated)))
}

#[utoipa::path(
    patch,
    path = "/api/documents/{id}/content",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = PatchDocumentContentRequest,
    responses((status = 200, body = Document))
)]
pub async fn patch_document_content(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<PatchDocumentContentRequest>,
) -> Result<Json<Document>, ApiError> {
    use application::documents::ports::realtime::realtime_port::EncryptedUpdate;
    use base64::Engine;

    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();

    if body.operations.is_empty() {
        return Err(ApiError::bad_request("missing_operations"));
    }

    // Check if any operation has encrypted_data (E2EE mode)
    let has_encrypted = body.operations.iter().any(|op| op.is_encrypted());

    let updated = if has_encrypted {
        // E2EE mode: convert operations with encrypted_data to EncryptedUpdate
        let encrypted_updates: Vec<EncryptedUpdate> = body
            .operations
            .iter()
            .filter_map(|op| {
                match op {
                    DocumentPatchOperationRequest::Insert {
                        encrypted_data: Some(encrypted_data),
                        nonce,
                        signature,
                        public_key,
                        ..
                    }
                    | DocumentPatchOperationRequest::Replace {
                        encrypted_data: Some(encrypted_data),
                        nonce,
                        signature,
                        public_key,
                        ..
                    } => {
                        let data = base64::engine::general_purpose::STANDARD
                            .decode(encrypted_data)
                            .ok()?;
                        let nonce_bytes = nonce.as_ref().and_then(|n| {
                            base64::engine::general_purpose::STANDARD.decode(n).ok()
                        });
                        let signature_bytes = signature.as_ref().and_then(|s| {
                            base64::engine::general_purpose::STANDARD.decode(s).ok()
                        });
                        let public_key_bytes = public_key.as_ref().and_then(|p| {
                            base64::engine::general_purpose::STANDARD.decode(p).ok()
                        });
                        Some(EncryptedUpdate {
                            data,
                            nonce: nonce_bytes,
                            signature: signature_bytes,
                            public_key: public_key_bytes,
                        })
                    }
                    _ => None,
                }
            })
            .collect();

        if encrypted_updates.is_empty() {
            return Err(ApiError::bad_request("no_encrypted_data_in_operations"));
        }

        service
            .patch_content(&actor, id, None, Some(&encrypted_updates))
            .await
            .map_err(map_service_error)?
    } else {
        // Plaintext mode: convert operations with text to DocumentPatchOperation
        let plaintext_operations: Vec<DocumentPatchOperation> = body
            .operations
            .iter()
            .filter_map(|op| op.to_plaintext_operation())
            .collect();

        if plaintext_operations.is_empty() {
            return Err(ApiError::bad_request("no_text_in_operations"));
        }

        service
            .patch_content(&actor, id, Some(&plaintext_operations), None)
            .await
            .map_err(map_service_error)?
    };

    Ok(Json(to_http_document(updated)))
}

