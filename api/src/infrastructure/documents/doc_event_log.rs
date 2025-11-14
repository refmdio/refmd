use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::application::ports::doc_event_log::DocEventLog;
use crate::infrastructure::db::PgPool;

pub struct PgDocEventLog {
    pool: PgPool,
}

impl PgDocEventLog {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocEventLog for PgDocEventLog {
    async fn append(
        &self,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<Value>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO doc_events (doc_id, event_type, payload)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(doc_id)
        .bind(event_type)
        .bind(payload)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
