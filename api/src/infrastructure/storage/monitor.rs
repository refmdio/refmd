use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Context;
use sqlx::Row;
use tokio::{self, sync::Mutex, time::sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{application::ports::storage_port::StorageResolverPort, infrastructure::db::PgPool};

/// Periodically verifies that metadata entries in `documents` / `files`
/// still have a corresponding object in the configured storage backend.
/// Missing files are logged once to avoid log spam and logged again when recovered.
pub struct StorageConsistencyMonitor {
    pool: PgPool,
    storage: Arc<dyn StorageResolverPort>,
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
        interval: Duration,
        batch_size: i64,
    ) -> Self {
        Self {
            pool,
            storage,
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
            r#"SELECT id, path
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
                    if flagged.insert(doc_id) {
                        warn!(document_id = %doc_id, path = %path, "storage_consistency_missing_document_file");
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
            r#"SELECT document_id, storage_path
               FROM files
               ORDER BY created_at DESC
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
                        warn!(document_id = %doc_id, attachment_path = %storage_path, "storage_consistency_missing_attachment");
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
