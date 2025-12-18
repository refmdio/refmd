use uuid::Uuid;

use super::StorageProjectionWorker;

impl StorageProjectionWorker {
    pub(super) async fn handle_folder_sync(&self, folder_id: Uuid) -> anyhow::Result<()> {
        self.storage.move_folder_subtree(folder_id).await?;
        Ok(())
    }
}

