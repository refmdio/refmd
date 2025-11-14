use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::application::services::doc_events::{DocEventRecord, DocEventSubscriber};
use crate::infrastructure::db::PgPool;
use crate::infrastructure::storage::{mark_dirty_delete_relative, mark_dirty_upsert_relative};

pub struct GitDirtyDocEventSubscriber {
    pool: PgPool,
}

impl GitDirtyDocEventSubscriber {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }

    async fn owner_id(&self, doc_id: Uuid) -> anyhow::Result<Option<Uuid>> {
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT owner_id FROM documents WHERE id = $1")
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(anyhow::Error::from)
            .map(|row| row.flatten())
    }

    async fn mark_upsert(
        &self,
        doc_id: Uuid,
        owner_hint: Option<Uuid>,
        repo_path: &str,
        is_text: bool,
        content_hash: Option<&str>,
    ) -> anyhow::Result<()> {
        let owner_id = match owner_hint {
            Some(id) => Some(id),
            None => self.owner_id(doc_id).await?,
        };
        let Some(owner_id) = owner_id else {
            return Ok(());
        };
        let trimmed = repo_path.trim_start_matches('/');
        let relative = format!("{}/{}", owner_id, trimmed);
        mark_dirty_upsert_relative(&self.pool, &relative, is_text, content_hash).await?;
        Ok(())
    }

    async fn mark_delete(
        &self,
        doc_id: Uuid,
        owner_hint: Option<Uuid>,
        repo_path: &str,
    ) -> anyhow::Result<()> {
        let owner_id = match owner_hint {
            Some(id) => Some(id),
            None => self.owner_id(doc_id).await?,
        };
        let Some(owner_id) = owner_id else {
            return Ok(());
        };
        let trimmed = repo_path.trim_start_matches('/');
        let relative = format!("{}/{}", owner_id, trimmed);
        mark_dirty_delete_relative(&self.pool, &relative).await?;
        Ok(())
    }
}

#[async_trait]
impl DocEventSubscriber for GitDirtyDocEventSubscriber {
    async fn handle_event(&self, event: &DocEventRecord) -> anyhow::Result<()> {
        let owner_hint = owner_id_from_payload(event.payload.as_ref());
        match event.event_type.as_str() {
            "document.ingest_upsert"
            | "document.created"
            | "document.content_updated"
            | "document.metadata_updated"
            | "document.archived"
            | "document.unarchived" => {
                if let Some(repo_path) = repo_path_from_payload(event.payload.as_ref()) {
                    let hash = content_hash_from_payload(event.payload.as_ref());
                    self.mark_upsert(event.doc_id, owner_hint, &repo_path, true, hash)
                        .await?;
                }
            }
            "document.deleted" => {
                if let Some(repo_path) = repo_path_from_payload(event.payload.as_ref()) {
                    self.mark_delete(event.doc_id, owner_hint, &repo_path)
                        .await?;
                }
            }
            "attachment.ingest_upsert" => {
                if let Some(repo_path) = repo_path_from_payload(event.payload.as_ref()) {
                    let hash = content_hash_from_payload(event.payload.as_ref());
                    self.mark_upsert(event.doc_id, owner_hint, &repo_path, false, hash)
                        .await?;
                }
            }
            "attachment.ingest_delete" => {
                if let Some(repo_path) = repo_path_from_payload(event.payload.as_ref()) {
                    self.mark_delete(event.doc_id, owner_hint, &repo_path)
                        .await?;
                }
            }
            _ => {
                info!(
                    event_type = event.event_type.as_str(),
                    "git_dirty_doc_event_ignored"
                );
            }
        }
        Ok(())
    }
}

fn repo_path_from_payload(payload: Option<&Value>) -> Option<String> {
    payload
        .and_then(|p| p.get("repo_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn content_hash_from_payload(payload: Option<&Value>) -> Option<&str> {
    payload
        .and_then(|p| p.get("content_hash"))
        .and_then(|v| v.as_str())
}

fn owner_id_from_payload(payload: Option<&Value>) -> Option<Uuid> {
    payload
        .and_then(|p| p.get("owner_id"))
        .and_then(|v| v.as_str())
        .and_then(|raw| Uuid::parse_str(raw).ok())
}
