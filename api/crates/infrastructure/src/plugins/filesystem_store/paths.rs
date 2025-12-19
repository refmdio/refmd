impl FilesystemPluginStore {
    pub(crate) fn is_valid_plugin_id(plugin_id: &str) -> bool {
        !plugin_id.is_empty() && PLUGIN_ID_RE.is_match(plugin_id)
    }

    pub(crate) fn ensure_valid_plugin_id(plugin_id: &str) -> anyhow::Result<()> {
        if Self::is_valid_plugin_id(plugin_id) {
            Ok(())
        } else {
            bail!("invalid plugin id");
        }
    }

    pub fn new(configured_dir: &str, limits: PluginExecutionLimits) -> anyhow::Result<Self> {
        let root = Self::resolve_root(configured_dir)?;
        Ok(Self {
            root,
            plugin_cache: Arc::new(RwLock::new(HashMap::new())),
            limits,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn global_root(&self) -> PathBuf {
        self.root.join("global")
    }

    pub fn user_root(&self, user_id: &Uuid) -> PathBuf {
        self.root.join(user_id.to_string())
    }

    pub fn user_plugin_manifest_path(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> PathBuf {
        self.user_root(user_id)
            .join(plugin_id)
            .join(version)
            .join("plugin.json")
    }

    pub fn global_plugin_manifest_path(&self, plugin_id: &str, version: &str) -> PathBuf {
        self.global_root()
            .join(plugin_id)
            .join(version)
            .join("plugin.json")
    }

    fn resolve_root(configured_dir: &str) -> anyhow::Result<PathBuf> {
        let configured = configured_dir.trim();
        if !configured.is_empty() {
            let path = PathBuf::from(configured);
            if !path.exists() {
                std::fs::create_dir_all(&path)?;
            }
            return path.canonicalize().or_else(|_| Ok(path));
        }
        let candidates = [PathBuf::from("./plugins"), PathBuf::from("../plugins")];
        for candidate in &candidates {
            if candidate.exists() {
                return candidate.canonicalize().or_else(|_| Ok(candidate.clone()));
            }
        }
        let fallback = PathBuf::from("./plugins");
        std::fs::create_dir_all(&fallback)?;
        match fallback.canonicalize() {
            Ok(p) => Ok(p),
            Err(_) => Ok(fallback),
        }
    }

    pub fn latest_version_dir(&self, base: &Path) -> anyhow::Result<Option<PathBuf>> {
        if !base.exists() {
            return Ok(None);
        }
        let mut best: Option<(PathBuf, String, Option<Version>)> = None;
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let candidate_name = entry.file_name().to_string_lossy().into_owned();
            let candidate_semver = Version::parse(&candidate_name).ok();
            match &best {
                Some((_path, current_name, current_semver)) => {
                    let is_newer = match (&candidate_semver, current_semver) {
                        (Some(candidate), Some(current)) => candidate > current,
                        (Some(_), None) => true,
                        (None, Some(_)) => false,
                        (None, None) => candidate_name.as_str() > current_name.as_str(),
                    };
                    if is_newer {
                        best = Some((entry.path(), candidate_name, candidate_semver));
                    }
                }
                None => best = Some((entry.path(), candidate_name, candidate_semver)),
            }
        }
        Ok(best.map(|(path, _, _)| path))
    }

    fn locate_plugin_dir(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        if !Self::is_valid_plugin_id(plugin) {
            return Ok(None);
        }
        if let Some(uid) = user_id {
            let base = self.user_root(&uid).join(plugin);
            if let Some(dir) = self.latest_version_dir(&base)? {
                return Ok(Some(dir));
            }
        }
        let base = self.global_root().join(plugin);
        self.latest_version_dir(&base)
    }
}
