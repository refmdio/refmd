#[async_trait]
impl PluginInstaller for FilesystemPluginStore {
    async fn install_for_user(
        &self,
        user_id: Uuid,
        archive: &[u8],
    ) -> Result<InstalledPlugin, PluginInstallError> {
        let archive_vec = archive.to_vec();
        let (_manifest, installed) = Self::read_manifest_from_archive(&archive_vec)?;

        let dest_root = self
            .user_root(&user_id)
            .join(&installed.id)
            .join(&installed.version);

        match tokio::fs::metadata(&dest_root).await {
            Ok(_) => {
                tokio::fs::remove_dir_all(&dest_root)
                    .await
                    .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(PluginInstallError::Storage(anyhow::anyhow!(err))),
        }
        if let Some(parent) = dest_root.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
        }
        tokio::fs::create_dir_all(&dest_root)
            .await
            .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;

        let dest_for_extract = dest_root.clone();
        let archive_for_extract = archive_vec;
        tokio::task::spawn_blocking(move || {
            FilesystemPluginStore::extract_archive(&archive_for_extract, &dest_for_extract)
        })
        .await
        .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))??;

        Ok(installed)
    }
}
