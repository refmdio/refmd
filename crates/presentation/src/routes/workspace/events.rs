//! Workspace SSE event streams

use application::dto::WorkspaceEventDto;
use application::types::WorkspaceEvent;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use crate::{AuthUser, WorkspaceSubState};

/// SSE endpoint for workspace events (invitation accepted, etc.)
///
/// Streams events relevant to the authenticated user's workspaces.
#[utoipa::path(
    get,
    path = "/api/workspaces/events",
    tag = "workspace",
    responses(
        (status = 200, description = "SSE event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn workspace_events(
    State(state): State<WorkspaceSubState>,
    auth_user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let user_id = auth_user.user_id;
    let receiver = state.workspace_event_bus.subscribe();

    let stream =
        BroadcastStream::new(receiver).filter_map(move |result: Result<WorkspaceEvent, _>| match result {
            Ok(ref event) if event.is_for_user(user_id) => {
                let dto = WorkspaceEventDto::from(event);
                let json = serde_json::to_string(&dto).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            _ => None,
        });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
