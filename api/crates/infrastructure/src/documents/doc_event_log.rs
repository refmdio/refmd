use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::doc_event_log::DocEventLog;

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
        workspace_id: Uuid,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<Value>,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"
            INSERT INTO doc_events (workspace_id, doc_id, event_type, payload)
            VALUES ($1, $2, $3, $4)
            "#,
            )
            .bind(workspace_id)
            .bind(doc_id)
            .bind(event_type)
            .bind(payload)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}
