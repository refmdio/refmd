use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{self, Stream, StreamExt};
use std::time::Duration;
use uuid::Uuid;

use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;

#[utoipa::path(
    get,
    path = "/api/me/plugins/updates",
    tag = "Plugins",
    responses((status = 200, description = "Plugin event stream", content_type = "text/event-stream"))
)]
pub async fn sse_updates(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let initial = stream::iter(vec![Ok(Event::default().event("ready").data("{}\n"))]);
    let event_stream = ctx
        .subscribe_plugin_events()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let broadcast = event_stream.filter_map(move |ev| {
        let user_id = user_id.clone();
        async move {
            if ev.user_id.is_some() && ev.user_id != Some(user_id) {
                return None;
            }
            let payload = ev.payload.to_string();
            Some(Ok(Event::default().event("update").data(payload)))
        }
    });
    let merged = initial.chain(broadcast);
    let keepalive = KeepAlive::new()
        .interval(Duration::from_secs(25))
        .text(":\n");
    Ok(Sse::new(merged).keep_alive(keepalive))
}
