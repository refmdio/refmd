#[async_trait]
impl PluginAssetStore for FilesystemPluginStore {
    async fn fetch_asset(
        &self,
        scope: PluginAssetStoreScope<'_>,
        plugin_id: &str,
        version: &str,
        relative_path: &str,
    ) -> anyhow::Result<PluginAssetPayload> {
        Self::ensure_valid_plugin_id(plugin_id)?;
        if version.is_empty()
            || version.len() > 128
            || version.contains("..")
            || version.contains(['/', '\\'])
        {
            bail!("invalid plugin version");
        }

        let base_root = match scope {
            PluginAssetStoreScope::Global => self.global_root(),
            PluginAssetStoreScope::User { owner_id } => self.user_root(owner_id),
        };

        let mut sanitized = PathBuf::new();
        for component in Path::new(relative_path).components() {
            match component {
                Component::Normal(part) => sanitized.push(part),
                Component::CurDir => continue,
                _ => bail!("invalid asset path"),
            }
        }
        if sanitized.as_os_str().is_empty() {
            bail!("invalid asset path");
        }

        let plugin_dir = base_root.join(plugin_id).join(version);
        let full_path = plugin_dir.join(&sanitized);
        if !full_path.starts_with(&plugin_dir) {
            bail!("invalid asset scope");
        }

        let bytes = tokio::fs::read(&full_path).await?;
        let content_type = mime_guess::from_path(&full_path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string();
        Ok(PluginAssetPayload {
            bytes,
            content_type,
        })
    }

    async fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()> {
        FilesystemPluginStore::remove_user_plugin_dir(self, user_id, plugin_id)
    }

    async fn list_latest_global_manifests(&self) -> anyhow::Result<Vec<LatestGlobalManifest>> {
        use std::io::ErrorKind;
        let mut items = Vec::new();
        let root = self.global_root();
        let mut entries = match tokio::fs::read_dir(&root).await {
            Ok(iter) => iter,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(items),
            Err(err) => return Err(err.into()),
        };

        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }

            let plugin_id = entry.file_name().to_string_lossy().to_string();
            let base = entry.path();
            let best = match self.latest_version_dir(&base) {
                Ok(Some(path)) => path,
                Ok(None) => continue,
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        plugin_id = plugin_id.as_str(),
                        path = ?base,
                        "resolve_global_plugin_version_failed"
                    );
                    continue;
                }
            };

            let version = best
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("0.0.0")
                .to_string();
            let manifest_path = best.join("plugin.json");
            let contents = match tokio::fs::read_to_string(&manifest_path).await {
                Ok(contents) => contents,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        plugin_id = plugin_id.as_str(),
                        version = version.as_str(),
                        path = ?manifest_path,
                        "read_global_plugin_manifest_failed"
                    );
                    continue;
                }
            };

            match serde_json::from_str::<serde_json::Value>(&contents) {
                Ok(json) => items.push(LatestGlobalManifest {
                    plugin_id: plugin_id.clone(),
                    version: version.clone(),
                    manifest: json,
                }),
                Err(err) => tracing::warn!(
                    error = ?err,
                    plugin_id = plugin_id.as_str(),
                    version = version.as_str(),
                    path = ?manifest_path,
                    "parse_global_plugin_manifest_failed"
                ),
            }
        }

        Ok(items)
    }

    async fn load_user_manifest(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        use std::io::ErrorKind;
        let manifest_path = self.user_plugin_manifest_path(user_id, plugin_id, version);
        match tokio::fs::read_to_string(&manifest_path).await {
            Ok(contents) => {
                let json = serde_json::from_str::<serde_json::Value>(&contents)?;
                Ok(Some(json))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}
