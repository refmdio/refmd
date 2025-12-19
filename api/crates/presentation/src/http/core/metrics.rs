use axum::{
    extract::State,
    http::{StatusCode, header},
    response::Response,
};

use crate::context::CoreContext;

pub async fn metrics_handler(State(ctx): State<CoreContext>) -> Result<Response, StatusCode> {
    let body = ctx.metrics().render();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(body.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
