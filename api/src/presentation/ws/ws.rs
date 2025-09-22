use std::pin::Pin;
use std::sync::Arc;

use crate::application::access::{self, Capability};
use crate::application::ports::realtime_port::RealtimeError;
use crate::bootstrap::app_context::{AppContext, DynRealtimeSink, DynRealtimeStream};
use crate::presentation::http::auth;
use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{Sink, Stream, StreamExt};
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthQuery {
    pub token: Option<String>,
    pub access_token: Option<String>,
}

// Uses AppContext as router state

#[utoipa::path(
    get,
    path = "/api/yjs/{id}",
    params(
        ("id" = String, Path, description = "Document ID (UUID)"),
        ("token" = Option<String>, Query, description = "JWT or share token"),
        ("Authorization" = Option<String>, Header, description = "Bearer token (JWT or share token)")
    ),
    responses(
        (status = 101, description = "Switching Protocols (WebSocket upgrade)"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "Realtime"
)]
pub async fn axum_ws_entry(
    #[allow(unused_variables)] Path(doc_id): Path<String>,
    ws: WebSocketUpgrade,
    Query(query): Query<AuthQuery>,
    headers: HeaderMap,
    State(state): State<AppContext>,
) -> Result<impl IntoResponse, StatusCode> {
    let token = query
        .token
        .or(query.access_token)
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok().map(|s| s.to_owned()))
                .and_then(|s| s.strip_prefix("Bearer ").map(|s| s.to_string()))
        })
        .or_else(|| {
            // Fallback to cookie `access_token`
            headers
                .get(axum::http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|cookie_hdr| {
                    for part in cookie_hdr.split(';') {
                        let kv = part.trim();
                        if let Some((k, v)) = kv.split_once('=') {
                            if k.trim() == "access_token" {
                                return Some(v.trim().to_string());
                            }
                        }
                    }
                    None
                })
        });

    // Try to parse document ID
    let doc_uuid = Uuid::parse_str(&doc_id).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Resolve actor capability
    let actor = token
        .as_deref()
        .and_then(|t| auth::resolve_actor_from_token_str(&state.cfg, t))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let share_access = state.share_access_port();
    let access_repo = state.access_repo();
    let cap = access::resolve_document(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        doc_uuid,
    )
    .await;
    if cap == Capability::None {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let can_edit = matches!(cap, Capability::Edit);

    let ctx = state.clone();
    Ok(ws.on_upgrade(move |socket| peer_axum(doc_id, socket, ctx, can_edit)))
}

// WebSocket <-> Vec<u8> sink adapter
struct WsBinarySink {
    inner: futures_util::stream::SplitSink<WebSocket, AxumMessage>,
}

impl Sink<Vec<u8>> for WsBinarySink {
    type Error = RealtimeError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(RealtimeError::new(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(AxumMessage::Binary(item))
            .map_err(RealtimeError::new)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(RealtimeError::new(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(RealtimeError::new(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// WebSocket -> Vec<u8> stream adapter
struct WsBinaryStream {
    inner: futures_util::stream::SplitStream<WebSocket>,
}

impl Stream for WsBinaryStream {
    type Item = Result<Vec<u8>, RealtimeError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(AxumMessage::Binary(b)))) => {
                    return std::task::Poll::Ready(Some(Ok(b)));
                }
                std::task::Poll::Ready(Some(Ok(AxumMessage::Text(_)))) => continue,
                std::task::Poll::Ready(Some(Ok(AxumMessage::Ping(_)))) => continue,
                std::task::Poll::Ready(Some(Ok(AxumMessage::Pong(_)))) => continue,
                std::task::Poll::Ready(Some(Ok(AxumMessage::Close(_)))) => {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Some(Err(RealtimeError::new(e))));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

// WS peer using Axum WebSocket
async fn peer_axum(doc_id: String, ws: WebSocket, ctx: AppContext, can_edit: bool) {
    tracing::debug!(%doc_id, "WS peer:upgrade");
    let (sink_raw, stream_raw) = ws.split();
    let sink_box: Pin<Box<WsBinarySink>> = Box::pin(WsBinarySink { inner: sink_raw });
    let sink_dyn: DynRealtimeSink = Arc::new(Mutex::new(
        sink_box as Pin<Box<dyn Sink<Vec<u8>, Error = RealtimeError> + Send + Sync>>,
    ));
    let stream_box: Pin<Box<WsBinaryStream>> = Box::pin(WsBinaryStream { inner: stream_raw });
    let stream_dyn: DynRealtimeStream =
        stream_box as Pin<Box<dyn Stream<Item = Result<Vec<u8>, RealtimeError>> + Send + Sync>>;

    tracing::debug!(%doc_id, "WS peer:subscribing");
    if let Err(e) = ctx
        .subscribe_realtime(&doc_id, sink_dyn, stream_dyn, can_edit)
        .await
    {
        tracing::warn!(%doc_id, error = %e, "WS subscription ended unexpectedly");
    } else {
        tracing::info!(%doc_id, "WS connection closed");
    }
}
