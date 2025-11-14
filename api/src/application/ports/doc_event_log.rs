use async_trait::async_trait;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[async_trait]
pub trait DocEventLog: Send + Sync {
    async fn append(
        &self,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<Value>,
    ) -> anyhow::Result<()>;

    async fn append_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<Value>,
    ) -> anyhow::Result<()>;
}
