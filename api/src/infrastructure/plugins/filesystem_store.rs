use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use extism::{Manifest, Plugin, Wasm};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use tokio::{sync::RwLock, task};
use uuid::Uuid;

use crate::application::dto::plugins::ExecResult;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_installer::{
    InstalledPlugin, PluginInstallError, PluginInstaller,
};
use crate::application::ports::plugin_runtime::PluginRuntime;

static PLUGIN_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid regex"));
static PLUGIN_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]+$").expect("valid regex"));

pub struct FilesystemPluginStore {
    root: PathBuf,
    plugin_cache: Arc<RwLock<HashMap<PathBuf, CachedPlugin>>>,
}

struct CachedPlugin {
    modified: SystemTime,
    plugin: Arc<Mutex<Plugin>>,
}

#[derive(Clone, Copy)]
enum InvocationKind {
    Exec,
    Render,
}

impl InvocationKind {
    fn as_str(&self) -> &'static str {
        match self {
            InvocationKind::Exec => "exec",
            InvocationKind::Render => "render",
        }
    }
}

impl FilesystemPluginStore {
    pub fn new(configured_dir: &str) -> anyhow::Result<Self> {
        let root = Self::resolve_root(configured_dir)?;
        Ok(Self {
            root,
            plugin_cache: Arc::new(RwLock::new(HashMap::new())),
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
        let mut best: Option<PathBuf> = None;
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            match &best {
                Some(current) => {
                    let current_name = current.file_name().and_then(|v| v.to_str()).unwrap_or("");
                    let candidate_name = entry.file_name().to_string_lossy().into_owned();
                    if candidate_name.as_str() > current_name {
                        best = Some(entry.path());
                    }
                }
                None => best = Some(entry.path()),
            }
        }
        Ok(best)
    }

    fn locate_plugin_dir(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        if let Some(uid) = user_id {
            let base = self.user_root(&uid).join(plugin);
            if let Some(dir) = self.latest_version_dir(&base)? {
                return Ok(Some(dir));
            }
        }
        let base = self.global_root().join(plugin);
        self.latest_version_dir(&base)
    }

    async fn resolve_backend_wasm_path(&self, plugin_dir: &Path) -> anyhow::Result<PathBuf> {
        let manifest_path = plugin_dir.join("plugin.json");
        let manifest_str = tokio::fs::read_to_string(&manifest_path)
            .await
            .with_context(|| format!("read plugin manifest at {}", manifest_path.display()))?;
        let manifest: JsonValue = serde_json::from_str(&manifest_str)
            .with_context(|| format!("parse plugin manifest at {}", manifest_path.display()))?;

        let wasm_rel = manifest
            .get("backend")
            .and_then(|b| b.get("wasm"))
            .and_then(|w| w.as_str())
            .unwrap_or("backend/plugin.wasm");
        let sanitized = Self::sanitize_relative_path(wasm_rel)?;
        Ok(plugin_dir.join(sanitized))
    }

    async fn load_plugin_instance(&self, plugin_dir: &Path) -> anyhow::Result<Arc<Mutex<Plugin>>> {
        let wasm_path = self.resolve_backend_wasm_path(plugin_dir).await?;
        let metadata = tokio::fs::metadata(&wasm_path)
            .await
            .with_context(|| format!("read metadata for {}", wasm_path.display()))?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        {
            let cache = self.plugin_cache.read().await;
            if let Some(entry) = cache.get(&wasm_path) {
                if entry.modified == modified {
                    return Ok(entry.plugin.clone());
                }
            }
        }

        let wasm_bytes = tokio::fs::read(&wasm_path)
            .await
            .with_context(|| format!("read wasm module at {}", wasm_path.display()))?;
        let wasm_key = wasm_path.clone();
        let plugin = task::spawn_blocking(move || -> anyhow::Result<Plugin> {
            let manifest = Manifest::new([Wasm::data(wasm_bytes)]);
            Plugin::new(manifest, [], true).context("create plugin")
        })
        .await
        .context("join extism initialization task")??;

        let plugin_arc = Arc::new(Mutex::new(plugin));
        let mut cache = self.plugin_cache.write().await;
        cache.insert(
            wasm_key,
            CachedPlugin {
                modified,
                plugin: plugin_arc.clone(),
            },
        );
        Ok(plugin_arc)
    }

    async fn invoke_plugin(
        &self,
        plugin_dir: &Path,
        function: &str,
        input: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let plugin = self.load_plugin_instance(plugin_dir).await?;
        let function = function.to_string();
        let output = task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let mut guard = plugin
                .lock()
                .map_err(|_| anyhow::anyhow!("extism plugin mutex poisoned"))?;
            let bytes: &[u8] = guard
                .call(&function, &input)
                .map_err(|err| anyhow::anyhow!(format!("extism call error: {err}")))?;
            Ok(bytes.to_vec())
        })
        .await
        .context("join extism call task")??;
        Ok(output)
    }

    fn sanitize_relative_path(path: &str) -> anyhow::Result<String> {
        let trimmed = path.trim();
        let without_root = trimmed.trim_start_matches('/');
        if without_root.is_empty() {
            anyhow::bail!("invalid backend wasm path");
        }
        if without_root
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            anyhow::bail!("invalid backend wasm path segment");
        }
        Ok(without_root.to_string())
    }

    fn build_invocation_context(
        user_id: Option<Uuid>,
        plugin: &str,
        invocation: &str,
        doc_id: Option<Uuid>,
        kind: InvocationKind,
    ) -> JsonValue {
        let timestamp = Utc::now().to_rfc3339();
        let mut ctx = JsonMap::new();
        ctx.insert("plugin".to_string(), json!({ "id": plugin }));
        ctx.insert("invocation".to_string(), json!(invocation));
        ctx.insert("timestamp".to_string(), json!(timestamp));
        ctx.insert(
            "invocation_meta".to_string(),
            json!({
                "name": invocation,
                "kind": kind.as_str(),
                "timestamp": timestamp,
            }),
        );
        if let Some(uid) = user_id {
            ctx.insert("user".to_string(), json!({ "id": uid }));
            ctx.insert("user_id".to_string(), json!(uid));
        }
        if let Some(doc) = doc_id {
            ctx.insert("doc".to_string(), json!({ "id": doc }));
            ctx.insert("doc_id".to_string(), json!(doc));
        }
        ctx.insert("kind".to_string(), json!(kind.as_str()));
        JsonValue::Object(ctx)
    }

    fn extract_doc_id(value: &JsonValue) -> Option<Uuid> {
        match value {
            JsonValue::Object(map) => {
                let direct_keys = ["docId", "doc_id", "doc", "document"];
                for key in direct_keys {
                    if let Some(candidate) = map.get(key) {
                        if let Some(id) = Self::value_to_uuid(candidate) {
                            return Some(id);
                        }
                    }
                }

                let nested_keys = ["options", "payload", "context", "meta"]; // fallback search
                for key in nested_keys {
                    if let Some(nested) = map.get(key) {
                        if let Some(id) = Self::extract_doc_id(nested) {
                            return Some(id);
                        }
                    }
                }
                None
            }
            JsonValue::String(s) => Uuid::parse_str(s).ok(),
            JsonValue::Array(items) => {
                for item in items {
                    if let Some(id) = Self::extract_doc_id(item) {
                        return Some(id);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn value_to_uuid(value: &JsonValue) -> Option<Uuid> {
        match value {
            JsonValue::String(s) => Uuid::parse_str(s).ok(),
            JsonValue::Object(obj) => obj
                .get("id")
                .and_then(|id| id.as_str())
                .and_then(|s| Uuid::parse_str(s).ok()),
            _ => None,
        }
    }

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
        let path = self.user_root(user_id).join(plugin_id);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok(())
    }
}

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

#[async_trait]
impl PluginAssetStore for FilesystemPluginStore {
    fn global_root(&self) -> std::path::PathBuf {
        FilesystemPluginStore::global_root(self)
    }

    fn user_root(&self, user_id: &Uuid) -> std::path::PathBuf {
        FilesystemPluginStore::user_root(self, user_id)
    }

    fn latest_version_dir(
        &self,
        base: &std::path::Path,
    ) -> anyhow::Result<Option<std::path::PathBuf>> {
        FilesystemPluginStore::latest_version_dir(self, base)
    }

    fn user_plugin_manifest_path(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> std::path::PathBuf {
        FilesystemPluginStore::user_plugin_manifest_path(self, user_id, plugin_id, version)
    }

    fn global_plugin_manifest_path(&self, plugin_id: &str, version: &str) -> std::path::PathBuf {
        FilesystemPluginStore::global_plugin_manifest_path(self, plugin_id, version)
    }

    fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()> {
        FilesystemPluginStore::remove_user_plugin_dir(self, user_id, plugin_id)
    }

    async fn list_latest_global_manifests(
        &self,
    ) -> anyhow::Result<Vec<(String, String, serde_json::Value)>> {
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
                Ok(json) => items.push((plugin_id.clone(), version.clone(), json)),
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

#[async_trait]
impl PluginRuntime for FilesystemPluginStore {
    async fn execute(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        action: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<Option<ExecResult>> {
        let plugin_dir = self.locate_plugin_dir(user_id, plugin)?;

        let Some(plugin_dir) = plugin_dir else {
            return Ok(None);
        };

        let doc_hint = Self::extract_doc_id(payload);
        let ctx =
            Self::build_invocation_context(user_id, plugin, action, doc_hint, InvocationKind::Exec);
        let input = json!({
            "action": action,
            "payload": payload,
            "ctx": ctx
        });

        let out = self
            .invoke_plugin(&plugin_dir, "exec", serde_json::to_vec(&input)?)
            .await?;

        if out.is_empty() {
            return Ok(None);
        }

        let res: ExecResult = serde_json::from_slice(&out)?;
        Ok(Some(res))
    }

    async fn render_placeholder(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        function: &str,
        request: &serde_json::Value,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let plugin_dir = self.locate_plugin_dir(user_id, plugin)?;
        let Some(plugin_dir) = plugin_dir else {
            return Ok(None);
        };

        let doc_hint = Self::extract_doc_id(request);

        let ctx = Self::build_invocation_context(
            user_id,
            plugin,
            function,
            doc_hint,
            InvocationKind::Render,
        );

        let envelope = match request.clone() {
            JsonValue::Object(mut map) => {
                map.insert("context".to_string(), ctx);
                JsonValue::Object(map)
            }
            other => json!({
                "payload": other,
                "context": ctx
            }),
        };

        let out = self
            .invoke_plugin(&plugin_dir, function, serde_json::to_vec(&envelope)?)
            .await?;
        if out.is_empty() {
            return Ok(None);
        }
        let value = serde_json::from_slice(&out)?;
        Ok(Some(value))
    }
}
