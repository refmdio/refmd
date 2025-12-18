impl GitWorkspaceService {
    async fn store_commit_snapshots(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<Vec<BlobKey>> {
        let mut stored = Vec::new();
        for (path, snapshot) in state.iter() {
            let key = blob_key(workspace_id, commit_id, path);
            let bytes = self.snapshot_bytes(snapshot).await?;
            if let Err(err) = self.git_storage.put_blob(&key, &bytes).await {
                for key in stored.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }
            stored.push(key);
        }
        Ok(stored)
    }

    async fn snapshot_bytes(&self, snapshot: &FileSnapshot) -> anyhow::Result<Vec<u8>> {
        match &snapshot.data {
            FileSnapshotData::Inline(bytes) => Ok(bytes.clone()),
            FileSnapshotData::StoragePath(path) => {
                let abs = self.storage.absolute_from_relative(path);
                self.storage.read_bytes(abs.as_path()).await
            }
        }
    }

    async fn load_file_snapshot(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        path: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = blob_key(workspace_id, commit_id, path);
        match self.git_storage.fetch_blob(&key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) => {
                // Treat missing blob as absence (e.g., binary or not stored).
                if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::NotFound {
                        return Ok(None);
                    }
                }
                if err.to_string().contains("not found") {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    #[allow(dead_code)]
    async fn state_from_commit_meta(
        &self,
        workspace_id: Uuid,
        meta: &CommitMeta,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();
        for path in meta.file_hash_index.keys() {
            let Some(bytes) = self
                .load_file_snapshot(workspace_id, &meta.commit_id, path)
                .await?
            else {
                continue;
            };
            let hash = sha256_hex(&bytes);
            let is_text = std::str::from_utf8(&bytes).is_ok();
            state.insert(
                path.clone(),
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::Inline(bytes),
                    is_text,
                },
            );
        }
        Ok(state)
    }
}
