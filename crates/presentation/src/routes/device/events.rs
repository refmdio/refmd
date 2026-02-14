//! Device SSE event streams

use application::dto::DeviceEventDto;
use axum::{
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::{AuthUser, DeviceEvent, DeviceSubState};

/// SSE endpoint for existing devices to receive pending device notifications
///
/// Streams events when:
/// - A new pending device is created for this user
/// - A pending device is approved
/// - A pending device expires/is removed
#[utoipa::path(
    get,
    path = "/api/devices/events",
    tag = "device",
    responses(
        (status = 200, description = "SSE event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn device_events(
    State(state): State<DeviceSubState>,
    auth_user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let user_id = auth_user.user_id;
    let receiver = state.device_event_bus.subscribe();

    let stream =
        BroadcastStream::<DeviceEvent>::new(receiver).filter_map(move |result| match result {
            Ok(event) if event.user_id() == user_id => {
                let dto = DeviceEventDto::from(&event);
                let json = serde_json::to_string(&dto).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            _ => None,
        });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// SSE endpoint for a new device waiting for approval
///
/// Streams events when:
/// - This pending device is approved
/// - This pending device expires/is removed
#[utoipa::path(
    get,
    path = "/api/devices/pending/{id}/events",
    tag = "device",
    params(
        ("id" = Uuid, Path, description = "Pending device ID")
    ),
    responses(
        (status = 200, description = "SSE event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pending device not found")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn pending_device_events(
    State(state): State<DeviceSubState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pending_device_id = application::types::DeviceId::from_uuid(id);
    let user_id = auth_user.user_id;
    let receiver = state.device_event_bus.subscribe();

    let stream =
        BroadcastStream::<DeviceEvent>::new(receiver).filter_map(move |result| match result {
            Ok(ref event)
                if event.pending_id() == Some(pending_device_id)
                    && event.user_id() == user_id =>
            {
                let dto = DeviceEventDto::from(event);
                let json = serde_json::to_string(&dto).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            _ => None,
        });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
