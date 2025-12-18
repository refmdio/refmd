impl FilesystemPluginStore {
    fn validate_manifest(
        manifest: &serde_json::Value,
    ) -> Result<(String, String), PluginInstallError> {
        let id = manifest
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PluginInstallError::InvalidPackage(anyhow::anyhow!("missing id")))?
            .to_string();
        let version = manifest
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PluginInstallError::InvalidPackage(anyhow::anyhow!("missing version")))?
            .to_string();

        if !PLUGIN_ID_RE.is_match(&id) {
            return Err(PluginInstallError::InvalidPackage(anyhow::anyhow!(
                "invalid plugin id"
            )));
        }
        if !PLUGIN_VERSION_RE.is_match(&version) {
            return Err(PluginInstallError::InvalidPackage(anyhow::anyhow!(
                "invalid plugin version"
            )));
        }
        Ok((id, version))
    }

    fn extract_archive(archive: &[u8], dest_root: &Path) -> Result<(), PluginInstallError> {
        let reader = std::io::Cursor::new(archive);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| PluginInstallError::InvalidPackage(anyhow::anyhow!(e)))?;

        let dest_root = dest_root
            .canonicalize()
            .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| PluginInstallError::InvalidPackage(anyhow::anyhow!(e)))?;
            let Some(rel_path) = file.enclosed_name().map(|p| p.to_path_buf()) else {
                continue;
            };

            if let Some(mode) = file.unix_mode() {
                if (mode & 0o170000) == 0o120000 {
                    continue;
                }
            }

            let outpath = dest_root.join(&rel_path);
            if !outpath.starts_with(&dest_root) {
                continue;
            }

            if file.is_dir() {
                std::fs::create_dir_all(&outpath)
                    .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
                }
                let mut outfile = std::fs::File::create(&outpath)
                    .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
                std::io::copy(&mut file, &mut outfile)
                    .map_err(|e| PluginInstallError::Storage(anyhow::anyhow!(e)))?;
            }
        }

        Ok(())
    }

    fn read_manifest_from_archive(
        archive_vec: &[u8],
    ) -> Result<(serde_json::Value, InstalledPlugin), PluginInstallError> {
        let reader = std::io::Cursor::new(archive_vec);
        let mut zip = zip::ZipArchive::new(reader)
            .map_err(|e| PluginInstallError::InvalidPackage(anyhow::anyhow!(e)))?;

        let mut manifest_json: Option<serde_json::Value> = None;
        for i in 0..zip.len() {
            let mut file = zip
                .by_index(i)
                .map_err(|e| PluginInstallError::InvalidPackage(anyhow::anyhow!(e)))?;
            if file.name().ends_with("plugin.json") {
                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .map_err(|e| PluginInstallError::InvalidPackage(anyhow::anyhow!(e)))?;
                manifest_json = serde_json::from_str(&contents).ok();
                break;
            }
        }

        let manifest = manifest_json.ok_or_else(|| {
            PluginInstallError::InvalidPackage(anyhow::anyhow!("plugin.json not found"))
        })?;
        let (id, version) = Self::validate_manifest(&manifest)?;
        Ok((manifest, InstalledPlugin { id, version }))
    }

    pub fn load_manifest(&self, manifest_path: &Path) -> Option<serde_json::Value> {
        std::fs::read_to_string(manifest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()> {
        Self::ensure_valid_plugin_id(plugin_id)?;
        let root = self.user_root(user_id);
        let path = root.join(plugin_id);
        if !path.starts_with(&root) {
            bail!("invalid plugin path");
        }
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok(())
    }
}
