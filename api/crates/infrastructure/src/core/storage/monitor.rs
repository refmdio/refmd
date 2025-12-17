use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Context;
use serde_json::json;
use sqlx::Row;
use tokio::{self, sync::Mutex, time::sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use application::core::ports::storage::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use application::core::ports::storage::storage_port::StorageResolverPort;
use application::core::ports::storage::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueue,
};
use domain::workspaces::permissions::PermissionSet;
use crate::core::db::PgPool;

/// Periodically verifies that metadata entries in `documents` / `files`
/// still have a corresponding object in the configured storage backend.
/// Missing files are logged once to avoid log spam and logged again when recovered.
pub struct StorageConsistencyMonitor {
    pool: PgPool,
    storage: Arc<dyn StorageResolverPort>,
    jobs: Arc<dyn StorageProjectionQueue>,
    ingest_queue: Arc<dyn StorageIngestQueue>,
    interval: Duration,
    batch_size: i64,
    doc_offset: Mutex<i64>,
    attachment_offset: Mutex<i64>,
    flagged_docs: Mutex<HashSet<Uuid>>,
    flagged_attachments: Mutex<HashSet<String>>, // storage_path keys
}

impl StorageConsistencyMonitor {
    pub fn new(
        pool: PgPool,
        storage: Arc<dyn StorageResolverPort>,
        jobs: Arc<dyn StorageProjectionQueue>,
        ingest_queue: Arc<dyn StorageIngestQueue>,
        interval: Duration,
        batch_size: i64,
    ) -> Self {
        Self {
            pool,
            storage,
            jobs,
            ingest_queue,
            interval,
            batch_size: batch_size.max(1),
            doc_offset: Mutex::new(0),
            attachment_offset: Mutex::new(0),
            flagged_docs: Mutex::new(HashSet::new()),
            flagged_attachments: Mutex::new(HashSet::new()),
        }
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            if let Err(err) = self.tick().await {
                error!(error = ?err, "storage_consistency_tick_failed");
            }
            sleep(self.interval).await;
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        self.scan_documents().await?;
        self.scan_attachments().await?;
        Ok(())
    }

    async fn scan_documents(&self) -> anyhow::Result<()> {
        let mut offset = self.doc_offset.lock().await;
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, path
               FROM documents
               WHERE path IS NOT NULL AND type <> 'folder'
               ORDER BY updated_at DESC
               LIMIT $1 OFFSET $2"#,
        )
        .bind(self.batch_size)
        .bind(*offset)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            *offset = 0;
            return Ok(());
        }

        for row in rows.iter() {
            let doc_id: Uuid = row.get("id");
            let path: String = row.try_get("path").context("documents.path missing")?;
            let workspace_id: Uuid = row.get("workspace_id");
            let abs = self.storage.absolute_from_relative(&path);
            match self.storage.exists(abs.as_path()).await {
                Ok(true) => {
                    let mut flagged = self.flagged_docs.lock().await;
                    if flagged.remove(&doc_id) {
                        info!(document_id = %doc_id, path = %path, "storage_consistency_document_restored");
                    }
                }
                Ok(false) => {
                    let mut flagged = self.flagged_docs.lock().await;
                    let newly_flagged = flagged.insert(doc_id);
                    drop(flagged);
                    if newly_flagged {
                        warn!(document_id = %doc_id, path = %path, "storage_consistency_missing_document_file");
                        self.enqueue_doc_resync(doc_id, workspace_id).await;
                    }
                }
                Err(err) => {
                    error!(document_id = %doc_id, path = %path, error = ?err, "storage_consistency_doc_check_failed");
                }
            }
        }

        *offset += rows.len() as i64;
        Ok(())
    }

    async fn scan_attachments(&self) -> anyhow::Result<()> {
        let mut offset = self.attachment_offset.lock().await;
        let rows = sqlx::query(
            r#"SELECT f.document_id, f.storage_path, d.owner_id, d.workspace_id
               FROM files f
               JOIN documents d ON d.id = f.document_id
               ORDER BY f.created_at DESC
               LIMIT $1 OFFSET $2"#,
        )
        .bind(self.batch_size)
        .bind(*offset)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            *offset = 0;
            return Ok(());
        }

        for row in rows.iter() {
            let doc_id: Uuid = row.get("document_id");
            let storage_path: String = row
                .try_get("storage_path")
                .context("files.storage_path missing")?;
            let owner_id: Uuid = row.get("owner_id");
            let workspace_id: Uuid = row.get("workspace_id");
            let abs = self.storage.absolute_from_relative(&storage_path);
            match self.storage.exists(abs.as_path()).await {
                Ok(true) => {
                    let mut flagged = self.flagged_attachments.lock().await;
                    if flagged.remove(&storage_path) {
                        info!(document_id = %doc_id, attachment_path = %storage_path, "storage_consistency_attachment_restored");
                    }
                }
                Ok(false) => {
                    let mut flagged = self.flagged_attachments.lock().await;
                    if flagged.insert(storage_path.clone()) {
                        warn!(document_id = %doc_id, attachment_path = %storage_path, workspace_id = %workspace_id, "storage_consistency_missing_attachment");
                        self.enqueue_attachment_delete(workspace_id, owner_id, &storage_path)
                            .await;
                    }
                }
                Err(err) => {
                    error!(document_id = %doc_id, attachment_path = %storage_path, error = ?err, "storage_consistency_attachment_check_failed");
                }
            }
        }

        *offset += rows.len() as i64;
        Ok(())
    }
}

impl StorageConsistencyMonitor {
    async fn enqueue_doc_resync(&self, doc_id: Uuid, workspace_id: Uuid) {
        if let Err(err) = self
            .jobs
            .enqueue_doc_job(
                workspace_id,
                doc_id,
                StorageProjectionJobKind::DocSync,
                Some("consistency_missing_document"),
            )
            .await
        {
            warn!(document_id = %doc_id, error = ?err, "storage_consistency_resync_enqueue_failed");
        }
    }

    async fn enqueue_attachment_delete(
        &self,
        workspace_id: Uuid,
        owner_id: Uuid,
        storage_path: &str,
    ) {
        let Some(repo_path) = repo_relative_from_storage(workspace_id, owner_id, storage_path)
        else {
            warn!(
                workspace_id = %workspace_id,
                owner_id = %owner_id,
                storage_path,
                "storage_consistency_attachment_repo_path_unparseable"
            );
            return;
        };
        if let Err(err) = self
            .ingest_queue
            .enqueue_event(
                workspace_id,
                workspace_id,
                None,
                &repo_path,
                "consistency",
                StorageIngestKind::Delete,
                None,
                Some(json!({
                    "source": "consistency_monitor",
                    "storage_path": storage_path,
                })),
                &PermissionSet::all().to_vec(),
            )
            .await
        {
            warn!(
                workspace_id = %workspace_id,
                owner_id = %owner_id,
                storage_path,
                error = ?err,
                "storage_consistency_attachment_delete_enqueue_failed"
            );
        }
    }
}

fn repo_relative_from_storage(
    workspace_id: Uuid,
    owner_id: Uuid,
    storage_path: &str,
) -> Option<String> {
    fn strip_prefix(storage_path: &str, prefix: Uuid) -> Option<String> {
        let trimmed = storage_path.trim_start_matches('/');
        let prefix_str = prefix.to_string();
        let rest = trimmed.strip_prefix(&prefix_str)?.trim_start_matches('/');
        if rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        }
    }

    strip_prefix(storage_path, workspace_id).or_else(|| strip_prefix(storage_path, owner_id))
}

#[cfg(test)]
mod tests {
    use super::repo_relative_from_storage;
    use uuid::Uuid;

    #[test]
    fn repo_relative_prefers_workspace_prefix_with_owner_fallback() {
        let workspace = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let ws_rel = format!("{}/docs/foo.md", workspace);
        let owner_rel = format!("{}/docs/bar.md", owner);
        assert_eq!(
            repo_relative_from_storage(workspace, owner, &ws_rel),
            Some("docs/foo.md".into())
        );
        assert_eq!(
            repo_relative_from_storage(workspace, owner, &owner_rel),
            Some("docs/bar.md".into())
        );
        assert_eq!(
            repo_relative_from_storage(workspace, owner, "/invalid"),
            None
        );
    }
}
