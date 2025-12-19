use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{self, Stream, StreamExt};
use std::time::Duration;

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::identity::auth::Bearer;

#[utoipa::path(
    get,
    path = "/api/me/plugins/updates",
    tag = "Plugins",
    responses((status = 200, description = "Plugin event stream", content_type = "text/event-stream"))
)]
pub async fn sse_updates(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, ApiError> {
    let user_id = crate::security::token::require_user_id(&ctx, bearer)
        .await
        .map_err(crate::security::token::map_actor_error)?;

    let initial = stream::iter(vec![Ok(Event::default().event("ready").data("{}\n"))]);
    let event_stream = ctx
        .subscribe_plugin_events()
        .await
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?;
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
