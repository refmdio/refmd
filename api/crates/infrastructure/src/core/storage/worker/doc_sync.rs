use uuid::Uuid;

use super::StorageProjectionWorker;

impl StorageProjectionWorker {
    pub(super) async fn handle_doc_sync(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.storage.sync_doc_paths(doc_id).await?;
        self.persist_markdown(doc_id).await
    }

    async fn persist_markdown(&self, doc_id: Uuid) -> anyhow::Result<()> {
        if let Some(export) = self.markdown.export_markdown_for_doc(&doc_id).await? {
            let path = self.resolver.build_doc_file_path(doc_id).await?;
            self.resolver
                .write_bytes(path.as_path(), &export.bytes)
                .await?;
            if let Some(repo_path) = export.repo_path.as_deref() {
                self.recent_exports
                    .record(export.workspace_id, repo_path, &export.content_hash);
            }
        }
        Ok(())
    }
}
