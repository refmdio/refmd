use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::{Client, error::SdkError};
use futures_util::StreamExt;
use tokio::fs;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::application::dto::plugins::ExecResult;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_event_publisher::PluginScopedEvent;
use crate::application::ports::plugin_installer::{
    InstalledPlugin, PluginInstallError, PluginInstaller,
};
use crate::application::ports::plugin_runtime::PluginRuntime;
use crate::bootstrap::config::Config;
use crate::infrastructure::plugins::event_bus_pg::PgPluginEventBus;
use crate::infrastructure::plugins::filesystem_store::FilesystemPluginStore;

const PLUGINS_PREFIX: &str = "plugins";
const GLOBAL_MANIFEST_CACHE_TTL_SECS: u64 = 300;

#[derive(Default)]
struct GlobalManifestCache {
    last_sync_epoch_secs: AtomicU64,
    refresh_lock: AsyncMutex<()>,
}

impl GlobalManifestCache {
    fn new() -> Self {
        Self {
            last_sync_epoch_secs: AtomicU64::new(0),
            refresh_lock: AsyncMutex::new(()),
        }
    }

    fn needs_refresh(&self, now_epoch_secs: u64) -> bool {
        let last = self.last_sync_epoch_secs.load(Ordering::Relaxed);
        if last == 0 {
            return true;
        }
        now_epoch_secs.saturating_sub(last) >= GLOBAL_MANIFEST_CACHE_TTL_SECS
    }

    fn mark_refreshed(&self, now_epoch_secs: u64) {
        self.last_sync_epoch_secs
            .store(now_epoch_secs, Ordering::Relaxed);
    }

    fn invalidate(&self) {
        self.last_sync_epoch_secs.store(0, Ordering::Relaxed);
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct UserPluginKey {
    user_id: Uuid,
    plugin: String,
}

impl UserPluginKey {
    fn new(user_id: Uuid, plugin: &str) -> Self {
        Self {
            user_id,
            plugin: plugin.to_string(),
        }
    }
}

fn is_manifest_affecting_event(event: &PluginScopedEvent) -> bool {
    if let Some(kind) = event.payload.get("event").and_then(|value| value.as_str()) {
        matches!(
            kind,
            "installed" | "uninstalled" | "updated" | "publish" | "unpublish"
        )
    } else {
        false
    }
}

fn epoch_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn build_client(cfg: &Config) -> anyhow::Result<Client> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(region) = &cfg.s3_region {
        loader = loader.region(Region::new(region.clone()));
    }
    let shared = loader.load().await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared);

    if let (Some(access), Some(secret)) = (&cfg.s3_access_key, &cfg.s3_secret_key) {
        builder = builder.credentials_provider(Credentials::new(
            access.clone(),
            secret.clone(),
            None,
            None,
            "refmd-s3-static",
        ));
    }
    if let Some(endpoint) = &cfg.s3_endpoint {
        builder = builder.endpoint_url(endpoint.clone());
    }
    if cfg.s3_use_path_style {
        builder = builder.force_path_style(true);
    }

    Ok(Client::from_conf(builder.build()))
}

async fn ensure_bucket(client: &Client, bucket: &str) -> anyhow::Result<()> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => return Ok(()),
        Err(SdkError::ServiceError(service_err)) => {
            if !matches!(service_err.err(), HeadBucketError::NotFound(_)) {
                return Err(anyhow!(service_err.err().to_string()));
            }
        }
        Err(err) => return Err(anyhow!(err.to_string())),
    }

    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(SdkError::ServiceError(service_err)) => {
            let msg = service_err.err().to_string();
            if msg.contains("BucketAlreadyOwnedByYou") || msg.contains("BucketAlreadyExists") {
                Ok(())
            } else {
                Err(anyhow!(msg))
            }
        }
        Err(err) => Err(anyhow!(err.to_string())),
    }
}

fn key_for(relative: &str) -> String {
    let trimmed = relative.trim_start_matches('/');
    if trimmed.is_empty() {
        PLUGINS_PREFIX.to_string()
    } else {
        format!("{}/{}", PLUGINS_PREFIX, trimmed)
    }
}

fn relative_from_key(key: &str) -> Option<String> {
    if key == PLUGINS_PREFIX {
        Some(String::new())
    } else {
        let prefix = format!("{}/", PLUGINS_PREFIX);
        key.strip_prefix(&prefix).map(|s| s.to_string())
    }
}

async fn list_keys(client: &Client, bucket: &str, prefix: &str) -> anyhow::Result<Vec<String>> {
    let mut keys = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = client.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(t) = &token {
            req = req.continuation_token(t);
        }
        let resp = req.send().await?;
        for obj in resp.contents() {
            if let Some(key) = obj.key() {
                keys.push(key.to_string());
            }
        }
        if resp.is_truncated().unwrap_or(false) {
            token = resp.next_continuation_token().map(|t| t.to_string());
        } else {
            break;
        }
    }
    Ok(keys)
}

async fn upload_directory(
    client: &Client,
    bucket: &str,
    root: &std::path::Path,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| anyhow!("{} is outside plugin root", entry.path().display()))?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let key = key_for(&rel_str);
        let data = fs::read(entry.path()).await?;
        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await?;
    }
    Ok(())
}

async fn delete_prefix(client: &Client, bucket: &str, rel_prefix: &str) -> anyhow::Result<()> {
    let key_prefix = key_for(rel_prefix);
    let keys = list_keys(client, bucket, &key_prefix).await?;
    if keys.is_empty() {
        return Ok(());
    }
    let mut batch: Vec<ObjectIdentifier> = Vec::new();
    for key in keys {
        if key.ends_with('/') {
            continue;
        }
        batch.push(ObjectIdentifier::builder().key(key).build()?);
        if batch.len() == 1000 {
            let chunk = batch.split_off(0);
            send_delete(client, bucket, chunk).await?;
        }
    }
    if !batch.is_empty() {
        send_delete(client, bucket, batch).await?;
    }
    Ok(())
}

async fn download_prefix(
    client: &Client,
    bucket: &str,
    rel_prefix: &str,
    local_root: &std::path::Path,
) -> anyhow::Result<()> {
    let key_prefix = key_for(rel_prefix);
    let keys = list_keys(client, bucket, &key_prefix).await?;
    for key in keys {
        if let Some(relative) = relative_from_key(&key) {
            if relative.is_empty() {
                continue;
            }
            let dest = local_root.join(&relative);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).await?;
            }
            let obj = client.get_object().bucket(bucket).key(key).send().await?;
            let data = obj.body.collect().await?.into_bytes();
            fs::write(&dest, data).await?;
        }
    }
    Ok(())
}

async fn send_delete(
    client: &Client,
    bucket: &str,
    batch: Vec<ObjectIdentifier>,
) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let delete = Delete::builder().set_objects(Some(batch)).build()?;
    client
        .delete_objects()
        .bucket(bucket)
        .delete(delete)
        .send()
        .await?;
    Ok(())
}

pub struct S3BackedPluginStore {
    local: Arc<FilesystemPluginStore>,
    client: Client,
    bucket: String,
    global_cache: GlobalManifestCache,
    user_refresh: Mutex<HashSet<UserPluginKey>>,
}

impl S3BackedPluginStore {
    pub async fn new(configured_dir: &str, cfg: &Config) -> anyhow::Result<Self> {
        let local = Arc::new(FilesystemPluginStore::new(configured_dir)?);
        let bucket = cfg
            .s3_bucket
            .clone()
            .context("S3 bucket must be configured when storage backend is S3")?;
        let client = build_client(cfg).await?;
        ensure_bucket(&client, &bucket).await?;

        if list_keys(&client, &bucket, PLUGINS_PREFIX)
            .await?
            .is_empty()
        {
            upload_directory(
                &client,
                &bucket,
                local.root(),
                local.global_root().as_path(),
            )
            .await?;
        }

        Ok(Self {
            local,
            client,
            bucket,
            global_cache: GlobalManifestCache::new(),
            user_refresh: Mutex::new(HashSet::new()),
        })
    }

    fn mark_user_plugin_dirty(&self, key: UserPluginKey) {
        let mut guard = self.user_refresh.lock().unwrap();
        guard.insert(key);
    }

    fn take_user_plugin_dirty(&self, key: &UserPluginKey) -> bool {
        let mut guard = self.user_refresh.lock().unwrap();
        guard.remove(key)
    }

    fn requeue_user_plugin_dirty(&self, key: UserPluginKey) {
        self.mark_user_plugin_dirty(key);
    }

    fn schedule_remove_user_plugin(&self, key: UserPluginKey) {
        self.take_user_plugin_dirty(&key);

        let store = self.local.clone();
        let user_id = key.user_id;
        let plugin = key.plugin.clone();

        tokio::spawn(async move {
            let plugin_for_log = plugin.clone();
            match tokio::task::spawn_blocking(move || {
                store.remove_user_plugin_dir(&user_id, &plugin)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::warn!(
                    error = ?err,
                    user_id = %user_id,
                    plugin = plugin_for_log.as_str(),
                    "remove_user_plugin_dir_failed"
                ),
                Err(err) => tracing::warn!(
                    error = ?err,
                    user_id = %user_id,
                    plugin = plugin_for_log.as_str(),
                    "remove_user_plugin_dir_join_failed"
                ),
            }
        });
    }

    fn runtime_store(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<(PathBuf, String)> {
        FilesystemPluginStore::ensure_valid_plugin_id(plugin)?;
        if let Some(uid) = user_id {
            Ok((
                self.local.user_root(&uid).join(plugin),
                format!("{}/{}", uid, plugin),
            ))
        } else {
            Ok((
                self.local.global_root().join(plugin),
                format!("global/{}", plugin),
            ))
        }
    }

    async fn ensure_local(&self, user_id: Option<Uuid>, plugin: &str) -> anyhow::Result<()> {
        let (base_dir, prefix) = self.runtime_store(user_id, plugin)?;
        let mut force_refresh = false;
        let mut retry_key: Option<UserPluginKey> = None;

        if let Some(uid) = user_id {
            let key = UserPluginKey::new(uid, plugin);
            if self.take_user_plugin_dirty(&key) {
                force_refresh = true;
                retry_key = Some(key);
            }
        }

        if !force_refresh && base_dir.exists() {
            if self.local.latest_version_dir(&base_dir)?.is_some() {
                return Ok(());
            }
        } else if force_refresh && base_dir.exists() {
            let _ = fs::remove_dir_all(&base_dir).await;
        }

        let result = download_prefix(&self.client, &self.bucket, &prefix, self.local.root()).await;
        if result.is_err() {
            if let Some(key) = retry_key {
                self.requeue_user_plugin_dirty(key);
            }
        }
        result
    }

    fn handle_plugin_event(&self, event: &PluginScopedEvent) {
        let kind = event
            .payload
            .get("event")
            .and_then(|value| value.as_str())
            .unwrap_or("");

        if is_manifest_affecting_event(event) {
            self.global_cache.invalidate();
        }

        if let Some(user_id) = event.user_id {
            if let Some(plugin_id) = event.payload.get("id").and_then(|v| v.as_str()) {
                let key = UserPluginKey::new(user_id, plugin_id);
                if kind == "uninstalled" {
                    self.schedule_remove_user_plugin(key);
                } else {
                    self.mark_user_plugin_dirty(key);
                }
            }
        }
    }

    pub fn spawn_event_listener(self: &Arc<Self>, bus: Arc<PgPluginEventBus>) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match bus.subscribe().await {
                    Ok(mut stream) => {
                        while let Some(event) = stream.next().await {
                            store.handle_plugin_event(&event);
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "plugin_manifest_event_listener_failed");
                    }
                }
                sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

#[async_trait]
impl PluginAssetStore for S3BackedPluginStore {
    fn global_root(&self) -> PathBuf {
        self.local.global_root()
    }

    fn user_root(&self, user_id: &Uuid) -> PathBuf {
        self.local.user_root(user_id)
    }

    fn latest_version_dir(&self, base: &std::path::Path) -> anyhow::Result<Option<PathBuf>> {
        self.local.latest_version_dir(base)
    }

    fn user_plugin_manifest_path(&self, user_id: &Uuid, plugin_id: &str, version: &str) -> PathBuf {
        self.local
            .user_plugin_manifest_path(user_id, plugin_id, version)
    }

    fn global_plugin_manifest_path(&self, plugin_id: &str, version: &str) -> PathBuf {
        self.local.global_plugin_manifest_path(plugin_id, version)
    }

    fn remove_user_plugin_dir(&self, user_id: &Uuid, plugin_id: &str) -> anyhow::Result<()> {
        self.local.remove_user_plugin_dir(user_id, plugin_id)?;
        let prefix = format!("{}/{}", user_id, plugin_id);
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        tokio::spawn(async move {
            let _ = delete_prefix(&client, &bucket, &prefix).await;
        });
        self.global_cache.invalidate();
        Ok(())
    }

    async fn list_latest_global_manifests(
        &self,
    ) -> anyhow::Result<Vec<(String, String, serde_json::Value)>> {
        let now = epoch_secs_now();
        if self.global_cache.needs_refresh(now) {
            let _guard = self.global_cache.refresh_lock.lock().await;
            let refreshed_now = epoch_secs_now();
            if self.global_cache.needs_refresh(refreshed_now) {
                download_prefix(&self.client, &self.bucket, "global", self.local.root()).await?;
                self.global_cache.mark_refreshed(refreshed_now);
            }
        }
        self.local.list_latest_global_manifests().await
    }

    async fn load_user_manifest(
        &self,
        user_id: &Uuid,
        plugin_id: &str,
        version: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        if !FilesystemPluginStore::is_valid_plugin_id(plugin_id) {
            return Ok(None);
        }
        self.ensure_local(Some(*user_id), plugin_id).await?;
        self.local
            .load_user_manifest(user_id, plugin_id, version)
            .await
    }
}

#[async_trait]
impl PluginInstaller for S3BackedPluginStore {
    async fn install_for_user(
        &self,
        user_id: Uuid,
        archive: &[u8],
    ) -> Result<InstalledPlugin, PluginInstallError> {
        let installed = self.local.install_for_user(user_id, archive).await?;
        let install_dir = self
            .local
            .user_root(&user_id)
            .join(&installed.id)
            .join(&installed.version);
        upload_directory(&self.client, &self.bucket, self.local.root(), &install_dir)
            .await
            .map_err(PluginInstallError::Storage)?;
        // Ensure subsequent manifest reads refetch latest artifacts after an install/update.
        self.global_cache.invalidate();
        Ok(installed)
    }
}

#[async_trait]
impl PluginRuntime for S3BackedPluginStore {
    async fn execute(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        action: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<Option<ExecResult>> {
        if !FilesystemPluginStore::is_valid_plugin_id(plugin) {
            return Ok(None);
        }
        self.ensure_local(user_id, plugin).await?;
        self.local.execute(user_id, plugin, action, payload).await
    }

    async fn render_placeholder(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        function: &str,
        request: &serde_json::Value,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        if !FilesystemPluginStore::is_valid_plugin_id(plugin) {
            return Ok(None);
        }
        self.ensure_local(user_id, plugin).await?;
        self.local
            .render_placeholder(user_id, plugin, function, request)
            .await
    }

    async fn permissions(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<Option<Vec<String>>> {
        if !FilesystemPluginStore::is_valid_plugin_id(plugin) {
            return Ok(None);
        }
        self.ensure_local(user_id, plugin).await?;
        self.local.permissions(user_id, plugin).await
    }
}
