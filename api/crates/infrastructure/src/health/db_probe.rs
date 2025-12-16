use std::sync::Arc;

use async_trait::async_trait;
use sqlx::Row;

use application::ports::health_probe::{HealthProbe, HealthStatus};
use crate::db::PgPool;

pub struct DatabaseHealthProbe {
    pool: PgPool,
}

impl DatabaseHealthProbe {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl HealthProbe for DatabaseHealthProbe {
    async fn probe(&self) -> anyhow::Result<HealthStatus> {
        let ok = sqlx::query("SELECT 1")
            .map(|row: sqlx::postgres::PgRow| row.get::<i32, _>(0))
            .fetch_one(&self.pool)
            .await
            .is_ok();
        if ok {
            Ok(HealthStatus::Healthy)
        } else {
            Ok(HealthStatus::Degraded)
        }
    }
}
