use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

use application::services::health::OverallHealth;
use crate::context::AppContext;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResp {
    pub status: &'static str,
}

#[utoipa::path(
    get,
    path = "/api/health",
    tag = "Health",
    responses((status = 200, body = HealthResp))
)]
pub async fn health(State(ctx): State<AppContext>) -> Json<HealthResp> {
    let service = ctx.health_service();
    let status = match service.status().await.unwrap_or(OverallHealth::Degraded) {
        OverallHealth::Ok => "ok",
        OverallHealth::Degraded => "degraded",
    };
    Json(HealthResp { status })
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/health", get(health)).with_state(ctx)
}
