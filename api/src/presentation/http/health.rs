use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;

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
pub async fn health(State(pool): State<PgPool>) -> Json<HealthResp> {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await
        .is_ok();
    let status = if db_ok { "ok" } else { "degraded" };
    Json(HealthResp { status })
}

pub fn routes(pool: PgPool) -> Router {
    Router::new().route("/health", get(health)).with_state(pool)
}
