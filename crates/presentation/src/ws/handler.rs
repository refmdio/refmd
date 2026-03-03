//! WebSocket document handler
//!
//! Handles the full lifecycle of a WebSocket connection for a document:
//! 1. HTTP upgrade with session authentication + RBAC check
//! 2. Initial `document` message with snapshot + updates
//! 3. Inbound message processing (update/snapshot/ephemeral)
//! 4. Outbound broadcast relay

use application::document::{
    CreateDocumentUpdateCommand, CreateSnapshotCommand,
    GetDocumentQuery, SnapshotQueryMode,
};
use application::dto::{DocumentSnapshotDto, DocumentUpdateDto};
use application::types::AppError;
use application::types::{DocumentId, DocumentSnapshotId};
use axum::{
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use super::connection_store::DocumentConnectionStore;
use super::messages::*;
use super::signature;
use crate::auth;
use crate::DocumentSubState;
use crate::state::type_aliases::DynSessionRepository;

/// Query parameters for WS connection
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct WsConnectParams {
    /// Connection mode: "complete" (full state) or "delta" (changes since known state)
    pub mode: Option<String>,
    /// Known snapshot ID for delta mode
    #[serde(rename = "knownSnapshotId")]
    #[param(rename = "knownSnapshotId")]
    pub known_snapshot_id: Option<String>,
    /// JSON-encoded map of known per-device update clocks for delta mode
    #[serde(rename = "knownSnapshotUpdateClocks")]
    #[param(rename = "knownSnapshotUpdateClocks")]
    pub known_snapshot_update_clocks: Option<String>,
}

/// State required for the WS handler
#[derive(Clone)]
pub struct WsState {
    pub document_sub_state: DocumentSubState,
    pub session_repo: DynSessionRepository,
    pub connection_store: DocumentConnectionStore,
    /// Allowed origins for CSWSH protection (from CORS_ORIGINS env var)
    pub allowed_origins: Vec<String>,
}

/// WebSocket document endpoint: GET /documents/{document_id}/ws
///
/// Upgrades the HTTP connection to a WebSocket for real-time document collaboration.
/// Requires session cookie authentication.
///
/// ## Protocol
///
/// After upgrade, the server sends an initial `document` message containing the
/// current snapshot + updates. Clients then exchange encrypted update/snapshot/ephemeral
/// messages through the WebSocket.
///
/// ## Client → Server messages
///
/// All messages use a signed envelope format (`WsInEnvelope`):
/// - **update**: Encrypted Y.js diff with clock and ref_snapshot_id
/// - **snapshot**: Encrypted full Y.js state with proof chain
/// - **ephemeral**: Encrypted cursor/presence data (not persisted)
///
/// ## Server → Client messages
///
/// See `WsOutMessage` for all possible server responses including
/// confirmations (`update-saved`, `snapshot-saved`) and broadcasts.
#[utoipa::path(
    get,
    path = "/api/documents/{document_id}/ws",
    tag = "document",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
        WsConnectParams,
    ),
    responses(
        (status = 101, description = "WebSocket upgrade successful"),
        (status = 400, description = "Bad request — invalid query parameters"),
        (status = 401, description = "Unauthorized — missing or invalid session"),
        (status = 403, description = "Forbidden — CSWSH origin rejected or insufficient permissions"),
        (status = 404, description = "Not found — document does not exist"),
    ),
)]
pub async fn ws_document(
    ws: WebSocketUpgrade,
    State(state): State<WsState>,
    Path(document_id): Path<Uuid>,
    Query(params): Query<WsConnectParams>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // CSWSH protection: if Origin header is present, it must match allowed origins.
    // Missing Origin is allowed (non-browser clients like curl).
    // Browsers always send Origin on WebSocket upgrades, so missing = non-browser.
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        let origin_str = origin.to_str().unwrap_or("");
        if !state.allowed_origins.iter().any(|a| a == origin_str) {
            return axum::http::StatusCode::FORBIDDEN.into_response();
        }
    }

    // Authenticate via session cookie
    let auth_user = match auth::authenticate(&headers, &state.session_repo).await {
        Ok(user) => user,
        Err(_) => {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // Pre-upgrade validation: RBAC + query parameter validation.
    // Rejects unauthorized users and invalid parameters before consuming WS resources.
    // Full data fetch is deferred to after room join (see handle_socket).
    let doc_id = DocumentId::from_uuid(document_id);
    let ds = &state.document_sub_state;
    let rbac_handler = application::document::GetDocumentHandler::new(
        ds.document_repo.clone(),
        ds.workspace_member_repo.clone(),
        ds.workspace_role_repo.clone(),
        ds.workspace_role_perm_repo.clone(),
    );
    let rbac_query = GetDocumentQuery {
        document_id: doc_id,
        user_id: auth_user.user_id,
    };
    match rbac_handler.handle(rbac_query).await {
        Ok(_) => {}
        Err(e) => {
            if e.is_not_found() {
                return axum::http::StatusCode::NOT_FOUND.into_response();
            } else if e.is_access_denied() {
                return axum::http::StatusCode::FORBIDDEN.into_response();
            } else {
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Parse and validate query parameters before upgrade so clients get proper HTTP errors
    // instead of silent disconnects.
    let parsed_params = match parse_ws_params(&params) {
        Ok(p) => p,
        Err(e) => {
            return match e {
                WsInitError::BadRequest => axum::http::StatusCode::BAD_REQUEST.into_response(),
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        }
    };

    // Limit inbound WS message size to 5 MiB to prevent abuse (DoS via oversized payloads).
    ws.max_message_size(5 * 1024 * 1024)
        .on_upgrade(move |socket| {
            handle_socket(socket, state, document_id, auth_user.user_id, parsed_params)
        })
}

async fn handle_socket(
    mut socket: WebSocket,
    state: WsState,
    document_id: Uuid,
    user_id: application::types::UserId,
    parsed_params: ParsedWsParams,
) {
    // Join the room FIRST so that any broadcasts during the DB read are queued
    // in the per-connection mpsc channel and delivered after the initial message.
    let (conn_id, mut targeted_rx, room) =
        state.connection_store.join(document_id, user_id.as_uuid());

    // Read document state from DB (after room join — no gap for missed broadcasts)
    let doc_id = DocumentId::from_uuid(document_id);
    let initial_msg = match build_initial_document_message(&state, doc_id, &parsed_params).await {
        Ok(msg) => msg,
        Err(e) => {
            let error_msg = match e {
                WsInitError::NotFound => WsOutMessage::DocumentNotFound,
                _ => WsOutMessage::DocumentError,
            };
            // Send error directly over the socket (outbound relay task hasn't started yet,
            // so room.send_to would enqueue into an unread channel).
            let json = serde_json::to_string(&error_msg).unwrap_or_default();
            let _ = socket.send(Message::Text(json.into())).await;
            state.connection_store.leave(document_id, conn_id);
            return;
        }
    };

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Send initial document message
    let json = serde_json::to_string(&initial_msg).unwrap_or_default();
    if ws_sender.send(Message::Text(json.into())).await.is_err() {
        state.connection_store.leave(document_id, conn_id);
        return;
    }

    let room_for_inbound = room.clone();
    let state_for_inbound = state.clone();
    let sender_conn_id = conn_id;

    // Inbound task: WS messages → process → targeted/broadcast
    let mut inbound = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_receiver.next().await {
            match msg {
                Message::Text(text) => {
                    handle_inbound_message(
                        &text,
                        &state_for_inbound,
                        &room_for_inbound,
                        document_id,
                        user_id,
                        sender_conn_id,
                    )
                    .await;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Outbound task: relay per-connection messages to the WebSocket
    let mut outbound = tokio::spawn(async move {
        while let Some(msg) = targeted_rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(_) => continue,
            };
            if ws_sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Wait for either task to finish, then abort the other
    tokio::select! {
        _ = &mut inbound => { outbound.abort(); }
        _ = &mut outbound => { inbound.abort(); }
    }

    state.connection_store.leave(document_id, conn_id);
}

enum WsInitError {
    NotFound,
    BadRequest,
    Internal,
}

/// Parsed WS query parameters, ready for use by the application layer.
struct ParsedWsParams {
    mode: SnapshotQueryMode,
    known_snapshot_id: Option<DocumentSnapshotId>,
}

/// Parse and validate WS query parameters before upgrade.
/// Returns parsed parameters or BadRequest for invalid input.
fn parse_ws_params(params: &WsConnectParams) -> Result<ParsedWsParams, WsInitError> {
    // Parse knownSnapshotId (used in both modes for anti-rollback proof chain)
    let known_snapshot_id = match params.known_snapshot_id.as_ref() {
        Some(id) => Some(DocumentSnapshotId::from_uuid(
            id.parse::<Uuid>().map_err(|_| WsInitError::BadRequest)?,
        )),
        None => None,
    };

    let mode = match params.mode.as_deref() {
        Some("delta") => {
            if known_snapshot_id.is_none() {
                return Err(WsInitError::BadRequest);
            }
            let known_clocks: std::collections::HashMap<String, i64> = match params
                .known_snapshot_update_clocks
                .as_deref()
            {
                Some(s) => serde_json::from_str(s).map_err(|_| WsInitError::BadRequest)?,
                None => return Err(WsInitError::BadRequest),
            };
            // Validate clock values fit in i32 range (DB column is integer)
            if known_clocks.values().any(|&v| v < 0 || v > i32::MAX as i64) {
                return Err(WsInitError::BadRequest);
            }
            SnapshotQueryMode::Delta { known_clocks }
        }
        Some("complete") | None => SnapshotQueryMode::Complete,
        Some(_) => return Err(WsInitError::BadRequest),
    };

    Ok(ParsedWsParams {
        mode,
        known_snapshot_id,
    })
}

async fn build_initial_document_message(
    state: &WsState,
    doc_id: DocumentId,
    parsed: &ParsedWsParams,
) -> Result<WsOutMessage, WsInitError> {
    let handler = state.document_sub_state.fetch_document_snapshot_handler();
    let query = application::document::FetchDocumentSnapshotQuery {
        document_id: doc_id,
        mode: parsed.mode.clone(),
        known_snapshot_id: parsed.known_snapshot_id,
    };

    let result = handler.handle(query).await.map_err(|e| {
        if e.is_not_found() {
            WsInitError::NotFound
        } else {
            tracing::error!("WS initial load error: {e}");
            WsInitError::Internal
        }
    })?;

    let snapshot = result.snapshot.as_ref().map(|s| snapshot_dto_to_ws(s));

    let updates = result.updates.into_iter().map(|u| update_dto_to_ws(u)).collect();

    let proof_chain = result
        .proof_chain
        .into_iter()
        .map(|p| WsSnapshotProof {
            snapshot_id: p.snapshot_id.to_string(),
            ciphertext_hash: p.ciphertext_hash,
            parent_snapshot_proof: p.parent_snapshot_proof,
        })
        .collect();

    Ok(WsOutMessage::Document {
        snapshot,
        updates,
        snapshot_proof_chain: proof_chain,
    })
}

async fn handle_inbound_message(
    text: &str,
    state: &WsState,
    room: &super::connection_store::DocumentRoom,
    document_id: Uuid,
    user_id: application::types::UserId,
    sender_conn_id: super::connection_store::ConnectionId,
) {
    let envelope: WsInEnvelope = match WsInEnvelope::from_text(text) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Invalid WS message: {e}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "unknown".to_string(),
                detail: format!("Invalid message format: {e}"),
            });
            return;
        }
    };

    match envelope.message_type() {
        IncomingMessageType::Snapshot => {
            handle_snapshot(state, room, document_id, user_id, sender_conn_id, &envelope).await;
        }
        IncomingMessageType::Update => {
            handle_update(state, room, document_id, user_id, sender_conn_id, &envelope).await;
        }
        IncomingMessageType::Ephemeral => {
            handle_ephemeral(state, room, document_id, user_id, sender_conn_id, &envelope).await;
        }
    }
}

async fn handle_update(
    state: &WsState,
    room: &super::connection_store::DocumentRoom,
    document_id: Uuid,
    user_id: application::types::UserId,
    sender_conn_id: super::connection_store::ConnectionId,
    envelope: &WsInEnvelope,
) {
    let raw_public_data = &envelope.raw_public_data;
    let pd = &envelope.public_data;

    // Verify docId matches the WS path document_id
    if pd.doc_id != document_id.to_string() {
        tracing::warn!("Update: docId mismatch: publicData.docId={} path={}", pd.doc_id, document_id);
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "update".to_string(),
            detail: "docId mismatch".to_string(),
        });
        return;
    }

    // Verify WS envelope signature
    if let Err(e) = signature::verify_ws_envelope_signature(
        signature::PREFIX_UPDATE,
        &envelope.ciphertext,
        &envelope.nonce,
        raw_public_data,
        &envelope.signature,
        &pd.signing_pub_key,
    ) {
        tracing::warn!("Update signature verification failed: {e}, publicData: {raw_public_data}");
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "update".to_string(),
            detail: "signature verification failed".to_string(),
        });
        return;
    }

    let ref_snapshot_id =
        match pd
            .ref_snapshot_id
            .as_ref()
            .and_then(|id| id.parse::<Uuid>().ok())
        {
            Some(uuid) => DocumentSnapshotId::from_uuid(uuid),
            None => {
                tracing::warn!("Update: missing or invalid ref_snapshot_id");
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "update".to_string(),
                    detail: "missing or invalid ref_snapshot_id".to_string(),
                });
                return;
            }
        };
    let clock = match pd.clock {
        Some(c) if c >= 0 => c,
        Some(c) => {
            tracing::warn!("Update: negative clock: {c}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: "clock must be non-negative".to_string(),
            });
            return;
        }
        None => {
            tracing::warn!("Update: missing clock");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: "missing clock".to_string(),
            });
            return;
        }
    };

    // Decode binary fields from base64url
    let update_data = match base64_url::decode(&envelope.ciphertext) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Update: ciphertext decode error: {e}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: format!("ciphertext decode error: {e}"),
            });
            return;
        }
    };
    let nonce = match base64_url::decode(&envelope.nonce) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("Update: nonce decode error: {e}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: format!("nonce decode error: {e}"),
            });
            return;
        }
    };
    let sig_bytes = match base64_url::decode(&envelope.signature) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Update: signature decode error: {e}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: format!("signature decode error: {e}"),
            });
            return;
        }
    };

    let key_version = match pd.key_version {
        Some(v) => v,
        None => {
            tracing::warn!("Update: missing keyVersion");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: "missing keyVersion".to_string(),
            });
            return;
        }
    };
    let timestamp = match pd.timestamp {
        Some(t) => t,
        None => {
            tracing::warn!("Update: missing timestamp");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: "missing timestamp".to_string(),
            });
            return;
        }
    };
    // Reject timestamps outside JS safe integer range (signature-protocol.md §数値型ルール)
    const JS_MAX_SAFE_INT: i64 = (1i64 << 53) - 1;
    if timestamp < -JS_MAX_SAFE_INT || timestamp > JS_MAX_SAFE_INT {
        tracing::warn!("Update: timestamp outside safe integer range: {timestamp}");
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "update".to_string(),
            detail: "timestamp outside safe integer range".to_string(),
        });
        return;
    }
    let client_update_hash = match pd.update_hash.as_ref() {
        Some(h) => h.clone(),
        None => {
            tracing::warn!("Update: missing updateHash");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "update".to_string(),
                detail: "missing updateHash".to_string(),
            });
            return;
        }
    };

    let handler = state.document_sub_state.create_update_handler();
    let command = CreateDocumentUpdateCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id,
        update_data,
        nonce,
        key_version,
        signature: sig_bytes,
        ref_snapshot_id,
        clock,
        device_signing_pub_key: pd.signing_pub_key.clone(),
        device_id: pd.device_id.clone(),
        public_data: raw_public_data.clone(),
        timestamp,
        client_update_hash,
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Confirmation to sender only
            room.send_to(sender_conn_id, WsOutMessage::UpdateSaved {
                snapshot_id: ref_snapshot_id.to_string(),
                clock: result.clock,
                version: result.version,
            });

            // RBAC check before broadcast: evict connections that lost permission.
            // Fail-closed: skip broadcast if the check could not complete (DB error).
            let rbac_ok = check_and_evict_unauthorized(state, room, document_id).await;

            if rbac_ok {
                // If sender was evicted by RBAC, skip broadcast of their update.
                // The update is already persisted (accepted risk: RBAC TOCTOU),
                // but we prevent active broadcast of unauthorized content.
                if !room.has_connection(sender_conn_id) {
                    return;
                }
                // Broadcast the update envelope to other clients (not sender)
                room.broadcast_except(sender_conn_id, WsOutMessage::Update(WsUpdateEnvelope {
                    ciphertext: envelope.ciphertext.clone(),
                    nonce: envelope.nonce.clone(),
                    signature: envelope.signature.clone(),
                    public_data: raw_public_data.clone(),
                    version: result.version,
                }));
            }
        }
        Err(e) => {
            tracing::warn!("Update save failed: {e}");
            if e.is_access_denied() {
                room.send_to(sender_conn_id, WsOutMessage::Unauthorized);
                return;
            }
            if e.is_not_found() {
                room.send_to(sender_conn_id, WsOutMessage::DocumentNotFound);
                return;
            }
            if e.is_invalid_input() {
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "update".to_string(),
                    detail: format!("{e}"),
                });
                return;
            }
            let requires_new_snapshot = e.is_snapshot_mismatch() || e.is_key_version_too_old();
            room.send_to(sender_conn_id, WsOutMessage::UpdateSaveFailed {
                snapshot_id: ref_snapshot_id.to_string(),
                clock,
                requires_new_snapshot,
            });
        }
    }
}

async fn handle_snapshot(
    state: &WsState,
    room: &super::connection_store::DocumentRoom,
    document_id: Uuid,
    user_id: application::types::UserId,
    sender_conn_id: super::connection_store::ConnectionId,
    envelope: &WsInEnvelope,
) {
    let raw_public_data = &envelope.raw_public_data;
    let pd = &envelope.public_data;

    // Verify docId matches the WS path document_id
    if pd.doc_id != document_id.to_string() {
        tracing::warn!("Snapshot: docId mismatch: publicData.docId={} path={}", pd.doc_id, document_id);
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "snapshot".to_string(),
            detail: "docId mismatch".to_string(),
        });
        return;
    }

    // Verify WS envelope signature
    if let Err(e) = signature::verify_ws_envelope_signature(
        signature::PREFIX_SNAPSHOT,
        &envelope.ciphertext,
        &envelope.nonce,
        raw_public_data,
        &envelope.signature,
        &pd.signing_pub_key,
    ) {
        tracing::warn!("Snapshot signature verification failed: {e}");
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "snapshot".to_string(),
            detail: "signature verification failed".to_string(),
        });
        return;
    }

    let parent_snapshot_id = match &pd.parent_snapshot_id {
        Some(id) if !id.is_empty() => match id.parse::<Uuid>() {
            Ok(uuid) => Some(DocumentSnapshotId::from_uuid(uuid)),
            Err(_) => {
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "snapshot".to_string(),
                    detail: "invalid parent_snapshot_id".to_string(),
                });
                return;
            }
        },
        _ => None, // Empty string or missing = genesis
    };

    let data = match base64_url::decode(&envelope.ciphertext) {
        Ok(d) => d,
        Err(e) => {
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: format!("ciphertext decode error: {e}"),
            });
            return;
        }
    };
    let nonce = match base64_url::decode(&envelope.nonce) {
        Ok(n) => n,
        Err(e) => {
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: format!("nonce decode error: {e}"),
            });
            return;
        }
    };
    let sig_bytes = match base64_url::decode(&envelope.signature) {
        Ok(s) => s,
        Err(e) => {
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: format!("signature decode error: {e}"),
            });
            return;
        }
    };

    let key_version = match pd.key_version {
        Some(v) => v,
        None => {
            tracing::warn!("Snapshot: missing keyVersion");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: "missing keyVersion".to_string(),
            });
            return;
        }
    };

    // Extract and validate client-generated snapshot ID
    let snapshot_id = match pd.snapshot_id.as_ref() {
        Some(id) => match id.parse::<Uuid>() {
            Ok(uuid) => DocumentSnapshotId::from_uuid(uuid),
            Err(_) => {
                tracing::warn!("Snapshot: invalid snapshotId format");
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "snapshot".to_string(),
                    detail: "invalid snapshotId format".to_string(),
                });
                return;
            }
        },
        None => {
            tracing::warn!("Snapshot: missing snapshotId");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: "missing snapshotId".to_string(),
            });
            return;
        }
    };

    // For genesis (no parent), reject non-empty parent fields to ensure canonical roots.
    let parent_snapshot_proof = pd.parent_snapshot_proof.clone().unwrap_or_default();
    let parent_snapshot_update_clocks = pd
        .parent_snapshot_update_clocks
        .clone()
        .unwrap_or_default();
    if parent_snapshot_id.is_none() {
        if !parent_snapshot_proof.is_empty() || !parent_snapshot_update_clocks.is_empty() {
            tracing::warn!("Snapshot: genesis with non-empty parent fields");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "snapshot".to_string(),
                detail: "genesis snapshot must have empty parentSnapshotProof and parentSnapshotUpdateClocks".to_string(),
            });
            return;
        }
    }

    let handler = state.document_sub_state.create_snapshot_handler();
    let command = CreateSnapshotCommand {
        snapshot_id,
        document_id: DocumentId::from_uuid(document_id),
        user_id,
        data,
        nonce,
        key_version,
        signature: sig_bytes,
        parent_snapshot_id,
        parent_snapshot_proof,
        parent_snapshot_update_clocks,
        device_signing_pub_key: pd.signing_pub_key.clone(),
        device_id: pd.device_id.clone(),
        public_data: raw_public_data.clone(),
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Confirmation to sender only
            room.send_to(sender_conn_id, WsOutMessage::SnapshotSaved {
                snapshot_id: result.snapshot_id.to_string(),
            });

            // RBAC check before broadcast: evict connections that lost permission.
            // Fail-closed: skip broadcast if the check could not complete (DB error).
            let rbac_ok = check_and_evict_unauthorized(state, room, document_id).await;

            if rbac_ok {
                // If sender was evicted by RBAC, skip broadcast of their snapshot.
                if !room.has_connection(sender_conn_id) {
                    return;
                }
                // Broadcast snapshot to other clients (not sender)
                room.broadcast_except(sender_conn_id, WsOutMessage::Snapshot {
                    snapshot_id: result.snapshot_id.to_string(),
                    snapshot: WsSnapshotEnvelope {
                        ciphertext: envelope.ciphertext.clone(),
                        nonce: envelope.nonce.clone(),
                        signature: envelope.signature.clone(),
                        public_data: raw_public_data.clone(),
                    },
                });
            }
        }
        Err(e) => {
            tracing::warn!("Snapshot save failed: {e}");
            if e.is_access_denied() {
                room.send_to(sender_conn_id, WsOutMessage::Unauthorized);
                return;
            }
            if e.is_not_found() {
                room.send_to(sender_conn_id, WsOutMessage::DocumentNotFound);
                return;
            }
            if e.is_invalid_input() {
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "snapshot".to_string(),
                    detail: format!("{e}"),
                });
                return;
            }
            // Return server's current state to sender only.
            // Pass the client's parent_snapshot_id as known_snapshot_id so the
            // server returns a proof chain for anti-rollback verification.
            let doc_id = DocumentId::from_uuid(document_id);
            let fallback_known_snapshot_id = pd
                .parent_snapshot_id
                .as_ref()
                .and_then(|id| id.parse::<Uuid>().ok())
                .map(DocumentSnapshotId::from_uuid);
            let fallback_params = ParsedWsParams {
                mode: SnapshotQueryMode::Complete,
                known_snapshot_id: fallback_known_snapshot_id,
            };
            let fallback = build_initial_document_message(
                state,
                doc_id,
                &fallback_params,
            )
            .await;

            let msg = match fallback {
                Ok(WsOutMessage::Document {
                    snapshot,
                    updates,
                    snapshot_proof_chain,
                }) => WsOutMessage::SnapshotSaveFailed {
                    snapshot,
                    updates,
                    snapshot_proof_chain,
                },
                _ => WsOutMessage::DocumentError,
            };
            room.send_to(sender_conn_id, msg);
        }
    }
}

/// Handle ephemeral messages (cursor positions, presence indicators).
///
/// Ephemeral payloads contain an encrypted session proof that recipients verify
/// client-side to confirm the sender holds the claimed session. The server does
/// not verify this proof (it cannot decrypt the payload).
async fn handle_ephemeral(
    state: &WsState,
    room: &super::connection_store::DocumentRoom,
    document_id: Uuid,
    user_id: application::types::UserId,
    sender_conn_id: super::connection_store::ConnectionId,
    envelope: &WsInEnvelope,
) {
    // Per-connection rate limit: drop excess ephemeral messages to prevent
    // DB amplification DoS via RBAC checks (websocket-scaling.md §DoS防止).
    if !room.check_ephemeral_rate_limit(sender_conn_id) {
        return;
    }

    let raw_public_data = &envelope.raw_public_data;
    // Verify docId matches the WS path document_id
    if envelope.public_data.doc_id != document_id.to_string() {
        tracing::warn!("Ephemeral: docId mismatch: publicData.docId={} path={}", envelope.public_data.doc_id, document_id);
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "ephemeral".to_string(),
            detail: "docId mismatch".to_string(),
        });
        return;
    }

    // Verify WS envelope signature
    if let Err(e) = signature::verify_ws_envelope_signature(
        signature::PREFIX_EPHEMERAL,
        &envelope.ciphertext,
        &envelope.nonce,
        raw_public_data,
        &envelope.signature,
        &envelope.public_data.signing_pub_key,
    ) {
        tracing::warn!("Ephemeral signature verification failed: {e}");
        room.send_to(sender_conn_id, WsOutMessage::ValidationError {
            message_type: "ephemeral".to_string(),
            detail: "signature verification failed".to_string(),
        });
        return;
    }

    // Device revocation check: verify the signing device is active and belongs to
    // this user. A revoked device should not be able to relay ephemeral messages.
    let signing_pub_key_bytes = match base64_url::decode(&envelope.public_data.signing_pub_key) {
        Ok(b) => b,
        Err(_) => {
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "ephemeral".to_string(),
                detail: "invalid signing_pub_key encoding".to_string(),
            });
            return;
        }
    };
    match state
        .document_sub_state
        .device_repo
        .find_active_by_signing_pub_key(&signing_pub_key_bytes)
        .await
    {
        Ok(Some(device)) => {
            if device.is_revoked() || device.user_id != user_id {
                tracing::warn!(
                    "Ephemeral: device revoked or user mismatch for signing key {}",
                    envelope.public_data.signing_pub_key,
                );
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "ephemeral".to_string(),
                    detail: "device revoked or not owned".to_string(),
                });
                return;
            }
            if device.id.to_string() != envelope.public_data.device_id {
                tracing::warn!(
                    "Ephemeral: deviceId mismatch: publicData.deviceId={} resolved={}",
                    envelope.public_data.device_id, device.id,
                );
                room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                    message_type: "ephemeral".to_string(),
                    detail: "deviceId mismatch".to_string(),
                });
                return;
            }
        }
        Ok(None) => {
            tracing::warn!(
                "Ephemeral: no active device found for signing key {}",
                envelope.public_data.signing_pub_key,
            );
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "ephemeral".to_string(),
                detail: "device not found".to_string(),
            });
            return;
        }
        Err(e) => {
            // Fail-closed: DB error prevents device verification
            tracing::warn!("Ephemeral: device lookup failed: {e}");
            room.send_to(sender_conn_id, WsOutMessage::ValidationError {
                message_type: "ephemeral".to_string(),
                detail: "device verification failed".to_string(),
            });
            return;
        }
    }

    // RBAC check before broadcast: unlike update/snapshot (which verify RBAC as part
    // of their DB write), ephemeral has no persistence step, so check permissions
    // before relaying to ensure the sender still has document:read.
    // Fail-closed: skip broadcast if the check could not complete (DB error).
    // DoS prevention is handled by per-connection rate limiting (see ConnectionInfo).
    let rbac_ok = check_and_evict_unauthorized(state, room, document_id).await;
    if !rbac_ok {
        return;
    }

    // If sender was evicted by the RBAC check, do not relay their message
    if !room.has_connection(sender_conn_id) {
        return;
    }

    // No persistence, broadcast to other clients only
    room.broadcast_except(sender_conn_id, WsOutMessage::EphemeralMessage(WsEphemeralEnvelope {
        ciphertext: envelope.ciphertext.clone(),
        nonce: envelope.nonce.clone(),
        signature: envelope.signature.clone(),
        public_data: raw_public_data.clone(),
    }));
}

/// Convert application DocumentSnapshotDto to WS wire format
fn snapshot_dto_to_ws(s: &DocumentSnapshotDto) -> WsSnapshotData {
    WsSnapshotData {
        id: s.id.to_string(),
        document_id: s.document_id.to_string(),
        latest_version: s.latest_version,
        data: base64_url::encode(&s.data),
        nonce: base64_url::encode(&s.nonce),
        key_version: s.key_version,
        signature: base64_url::encode(&s.signature),
        ciphertext_hash: s.ciphertext_hash.clone(),
        clocks: s.clocks.clone(),
        parent_snapshot_update_clocks: s.parent_snapshot_update_clocks.clone(),
        parent_snapshot_proof: s.parent_snapshot_proof.clone(),
        created_by_device: s.created_by_device.clone(),
        public_data: s.public_data.clone(),
        created_at: s.created_at.to_rfc3339(),
    }
}

/// Lazy RBAC check before broadcast: verify each connected user still has document:read
/// permission. Evict any users who have lost access.
///
/// This implements the design requirement (websocket-scaling.md:159):
/// "Lazy RBAC check at broadcast time, auto-disconnect connections that lost permissions"
///
/// Returns `true` if the check completed successfully (safe to proceed with broadcast).
/// Returns `false` if a DB error prevented the check (fail-closed: caller should skip broadcast).
async fn check_and_evict_unauthorized(
    state: &WsState,
    room: &super::connection_store::DocumentRoom,
    document_id: Uuid,
) -> bool {
    // Check ALL connections including sender (sender's permission may have been revoked too)
    let user_ids = room.connected_user_ids();
    if user_ids.is_empty() {
        return true;
    }

    let doc_id = DocumentId::from_uuid(document_id);
    let ds = &state.document_sub_state;
    let handler = application::document::GetDocumentHandler::new(
        ds.document_repo.clone(),
        ds.workspace_member_repo.clone(),
        ds.workspace_role_repo.clone(),
        ds.workspace_role_perm_repo.clone(),
    );

    for uid in user_ids {
        let user_id = application::types::UserId::from_uuid(uid);
        let query = GetDocumentQuery {
            document_id: doc_id,
            user_id,
        };

        match handler.handle(query).await {
            Ok(_) => {} // Still has document:read
            Err(e) if e.is_not_found() => {
                tracing::info!(
                    "Lazy RBAC eviction: document {document_id} not found, disconnecting user {uid}",
                );
                room.evict_user(uid, WsOutMessage::DocumentNotFound);
            }
            Err(e) if e.is_access_denied() => {
                tracing::info!(
                    "Lazy RBAC eviction: user {uid} lost document:read, disconnecting from document {document_id}",
                );
                room.evict_user(uid, WsOutMessage::Unauthorized);
            }
            Err(e) => {
                // Fail-closed: DB error prevents authoritative permission check.
                // Skip broadcast rather than potentially leaking data to unauthorized users.
                tracing::warn!(
                    "Lazy RBAC check failed for user {uid} on document {document_id}: {e}. Skipping broadcast (fail-closed).",
                );
                return false;
            }
        }
    }

    true
}

/// Convert application DocumentUpdateDto to WS wire format
fn update_dto_to_ws(u: DocumentUpdateDto) -> WsUpdateData {
    WsUpdateData {
        update_data: base64_url::encode(&u.update_data),
        nonce: base64_url::encode(&u.nonce),
        key_version: u.key_version,
        update_hash: u.update_hash,
        signature: base64_url::encode(&u.signature),
        timestamp: u.timestamp,
        snapshot_id: u.snapshot_id.to_string(),
        clock: u.clock,
        version: u.version,
        device_signing_pub_key: u.device_signing_pub_key,
        public_data: u.public_data,
    }
}
