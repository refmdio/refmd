use std::sync::Arc;

use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::plugins::ports::plugin_asset_store::{
    LatestGlobalManifest, PluginAssetPayload, PluginAssetStore, PluginAssetStoreScope,
};
use crate::plugins::ports::plugin_event_publisher::{PluginEventPublisher, PluginScopedEvent};
use crate::plugins::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::plugins::ports::plugin_installer::{InstalledPlugin, PluginInstaller};
use crate::plugins::ports::plugin_package_fetcher::PluginPackageFetcher;
use crate::plugins::services::asset_signer::{AssetScope, AssetSigner};
use crate::plugins::use_cases::install_from_url::{InstallPluginError, InstallPluginFromUrl};
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::plugins::events::PluginEventKind;
use domain::plugins::scope::{PluginInstallationStatus, PluginScope};

#[derive(Debug, Clone)]
pub struct PluginManifestItem {
    pub id: String,
    pub name: Option<String>,
    pub version: String,
    pub scope: PluginScope,
    pub mounts: Vec<String>,
    pub frontend: Value,
    pub permissions: Vec<String>,
    pub config: Value,
    pub ui: Value,
    pub author: Option<String>,
    pub repository: Option<String>,
}

pub struct PluginAssetRequest<'a> {
    pub scope: AssetRequestScope<'a>,
    pub plugin_id: &'a str,
    pub version: &'a str,
    pub path: &'a str,
    pub expires_at: i64,
    pub signature: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub enum AssetRequestScope<'a> {
    Global,
    User {
        owner_id: Uuid,
        share_token: Option<&'a str>,
    },
}

pub struct PluginManagementService {
    installations: Arc<dyn PluginInstallationRepository>,
    assets: Arc<dyn PluginAssetStore>,
    event_publisher: Arc<dyn PluginEventPublisher>,
    asset_signer: Arc<AssetSigner>,
    manifest_ttl_secs: u64,
    package_fetcher: Arc<dyn PluginPackageFetcher>,
    plugin_installer: Arc<dyn PluginInstaller>,
}

#[async_trait]
pub trait PluginManagementServiceFacade: Send + Sync {
    async fn install_from_url(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        url: &str,
        token: Option<&str>,
    ) -> Result<InstalledPlugin, InstallPluginError>;

    async fn uninstall(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        plugin_id: &str,
    ) -> Result<(), ServiceError>;

    async fn manifests_for_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<PluginManifestItem>, ServiceError>;

    async fn fetch_asset(
        &self,
        request: PluginAssetRequest<'_>,
    ) -> Result<PluginAssetPayload, ServiceError>;
}

#[async_trait]
impl PluginManagementServiceFacade for PluginManagementService {
    async fn install_from_url(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        url: &str,
        token: Option<&str>,
    ) -> Result<InstalledPlugin, InstallPluginError> {
        self.install_from_url(workspace_id, user_id, permissions, url, token)
            .await
    }

    async fn uninstall(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        plugin_id: &str,
    ) -> Result<(), ServiceError> {
        self.uninstall(workspace_id, user_id, permissions, plugin_id)
            .await
    }

    async fn manifests_for_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<PluginManifestItem>, ServiceError> {
        self.manifests_for_workspace(workspace_id, user_id).await
    }

    async fn fetch_asset(
        &self,
        request: PluginAssetRequest<'_>,
    ) -> Result<PluginAssetPayload, ServiceError> {
        self.fetch_asset(request).await
    }
}

impl PluginManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installations: Arc<dyn PluginInstallationRepository>,
        assets: Arc<dyn PluginAssetStore>,
        event_publisher: Arc<dyn PluginEventPublisher>,
        asset_signer: Arc<AssetSigner>,
        manifest_ttl_secs: u64,
        package_fetcher: Arc<dyn PluginPackageFetcher>,
        plugin_installer: Arc<dyn PluginInstaller>,
    ) -> Self {
        Self {
            installations,
            assets,
            event_publisher,
            asset_signer,
            manifest_ttl_secs,
            package_fetcher,
            plugin_installer,
        }
    }

    pub async fn install_from_url(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        _permissions: &PermissionSet,
        url: &str,
        token: Option<&str>,
    ) -> Result<InstalledPlugin, InstallPluginError> {
        let uc = InstallPluginFromUrl {
            fetcher: self.package_fetcher.as_ref(),
            installer: self.plugin_installer.as_ref(),
            events: self.event_publisher.as_ref(),
            installations: self.installations.as_ref(),
        };
        uc.execute(workspace_id, user_id, url, token).await
    }

    pub async fn manifests_for_workspace(
        &self,
        workspace_id: Uuid,
        _user_id: Uuid,
    ) -> Result<Vec<PluginManifestItem>, ServiceError> {
        let mut items = Vec::new();

        let global = self
            .assets
            .list_latest_global_manifests()
            .await
            .map_err(ServiceError::from)?;
        for LatestGlobalManifest {
            plugin_id,
            version,
            manifest,
        } in global
        {
            if let Some(item) = self.build_manifest_item(
                &plugin_id,
                &version,
                &manifest,
                ManifestScope::Global,
                None,
            ) {
                items.push(item);
            }
        }

        let installs = self
            .installations
            .list_for_workspace(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        for inst in installs
            .into_iter()
            .filter(|i| i.status == PluginInstallationStatus::Enabled)
        {
            match self
                .assets
                .load_user_manifest(&workspace_id, &inst.plugin_id, &inst.version)
                .await
            {
                Ok(Some(manifest)) => {
                    if let Some(item) = self.build_manifest_item(
                        &inst.plugin_id,
                        &inst.version,
                        &manifest,
                        ManifestScope::User {
                            user_id: workspace_id,
                        },
                        None,
                    ) {
                        items.push(item);
                    }
                }
                Ok(None) => {}
                Err(err) => warn!(
                    error = ?err,
                    plugin = inst.plugin_id.as_str(),
                    version = inst.version.as_str(),
                    workspace_id = %workspace_id,
                    "workspace_manifest_load_failed"
                ),
            }
        }

        items.sort_by(|a, b| {
            let scope_a = if a.scope == PluginScope::User { 0 } else { 1 };
            let scope_b = if b.scope == PluginScope::User { 0 } else { 1 };
            scope_a
                .cmp(&scope_b)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.version.cmp(&b.version))
        });

        Ok(items)
    }

    pub async fn uninstall(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        _permissions: &PermissionSet,
        plugin_id: &str,
    ) -> Result<(), ServiceError> {
        validate_plugin_id(plugin_id)?;
        self.installations
            .remove(workspace_id, plugin_id)
            .await
            .map_err(ServiceError::from)?;

        if let Err(err) = self
            .assets
            .remove_user_plugin_dir(&workspace_id, plugin_id)
            .await
        {
            warn!(
                error = ?err,
                workspace_id = %workspace_id,
                plugin = plugin_id,
                "plugin_uninstall_cleanup_failed"
            );
        }

        let event = PluginScopedEvent {
            user_id: Some(user_id),
            workspace_id: Some(workspace_id),
            payload: json!({
                "event": PluginEventKind::Uninstalled.as_str(),
                "id": plugin_id,
                "workspace_id": workspace_id,
            }),
        };
        let _ = self.event_publisher.publish(&event).await;
        Ok(())
    }

    pub async fn fetch_asset(
        &self,
        request: PluginAssetRequest<'_>,
    ) -> Result<PluginAssetPayload, ServiceError> {
        validate_plugin_id(request.plugin_id)?;
        validate_plugin_version(request.version)?;
        let normalized_path = normalize_manifest_path(request.path)?;

        let mut scoped_owner_id: Option<Uuid> = None;
        let (scope, store_scope) = match request.scope {
            AssetRequestScope::Global => (AssetScope::Global, PluginAssetStoreScope::Global),
            AssetRequestScope::User {
                owner_id,
                share_token,
            } => {
                let owner_ref = scoped_owner_id.insert(owner_id);
                (
                    AssetScope::User {
                        owner_id,
                        share_token,
                    },
                    PluginAssetStoreScope::User {
                        owner_id: owner_ref,
                    },
                )
            }
        };

        if !self.asset_signer.verify_url(
            scope,
            request.plugin_id,
            request.version,
            &normalized_path,
            request.expires_at,
            request.signature,
        ) {
            return Err(ServiceError::Unauthorized);
        }

        self.assets
            .fetch_asset(
                store_scope,
                request.plugin_id,
                request.version,
                &normalized_path,
            )
            .await
            .map_err(|err| {
                if err.downcast_ref::<std::io::Error>().is_some() {
                    ServiceError::NotFound
                } else {
                    ServiceError::Unexpected(err)
                }
            })
    }

    fn build_manifest_item(
        &self,
        id: &str,
        version: &str,
        manifest: &Value,
        scope: ManifestScope,
        share_token: Option<&str>,
    ) -> Option<PluginManifestItem> {
        let name = manifest
            .get("name")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let mounts = manifest
            .get("mounts")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|| vec![format!("/{id}/*")]);
        let frontend_value = manifest.get("frontend");
        let (frontend_entry, frontend_mode) = match frontend_value {
            Some(v) => {
                let entry = v.get("entry").and_then(|x| x.as_str());
                let mode = v
                    .get("mode")
                    .and_then(|x| x.as_str())
                    .unwrap_or("esm")
                    .to_string();
                (entry.map(|e| e.to_string()), Some(mode))
            }
            None => (None, None),
        };
        let permissions = manifest
            .get("permissions")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        let config = manifest.get("config").cloned().unwrap_or_else(|| json!({}));
        let ui = manifest.get("ui").cloned().unwrap_or_else(|| json!({}));
        let author = manifest
            .get("author")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let repository = manifest
            .get("repository")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());

        let signer_scope = match scope {
            ManifestScope::Global => AssetScope::Global,
            ManifestScope::User { user_id } => AssetScope::User {
                owner_id: user_id,
                share_token,
            },
        };

        let frontend = match frontend_entry {
            Some(entry) => {
                let normalized = match normalize_manifest_path(&entry) {
                    Ok(path) => path,
                    Err(err) => {
                        warn!(error = ?err, plugin = id, version = version, "manifest_entry_invalid");
                        return None;
                    }
                };
                let signed = self.asset_signer.sign_url(
                    signer_scope,
                    id,
                    version,
                    &normalized,
                    self.manifest_ttl_secs,
                );
                serde_json::json!({
                    "entry": signed,
                    "mode": frontend_mode.unwrap_or_else(|| "esm".to_string()),
                })
            }
            None => Value::Null,
        };

        Some(PluginManifestItem {
            id: id.to_string(),
            name,
            version: version.to_string(),
            scope: scope.as_plugin_scope(),
            mounts,
            frontend,
            permissions,
            config,
            ui,
            author,
            repository,
        })
    }
}

#[derive(Clone, Copy)]
enum ManifestScope {
    Global,
    User { user_id: Uuid },
}

impl ManifestScope {
    fn as_plugin_scope(&self) -> PluginScope {
        match self {
            ManifestScope::Global => PluginScope::Global,
            ManifestScope::User { .. } => PluginScope::User,
        }
    }
}

pub fn validate_plugin_id(id: &str) -> Result<(), ServiceError> {
    const MAX_LEN: usize = 128;
    if id.is_empty() || id.len() > MAX_LEN {
        return Err(ServiceError::BadRequest("invalid plugin id"));
    }
    if id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("invalid plugin id"))
    }
}

pub fn validate_plugin_version(version: &str) -> Result<(), ServiceError> {
    const MAX_LEN: usize = 128;
    if version.is_empty() || version.len() > MAX_LEN {
        return Err(ServiceError::BadRequest("invalid plugin version"));
    }
    if version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("invalid plugin version"))
    }
}

pub fn normalize_manifest_path(raw: &str) -> Result<String, ServiceError> {
    let mut trimmed = raw.trim();
    while let Some(stripped) = trimmed.strip_prefix("./") {
        trimmed = stripped;
    }
    trimmed = trimmed.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains("..") || trimmed.contains('\\') {
        return Err(ServiceError::BadRequest("invalid manifest path"));
    }
    if trimmed
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ServiceError::BadRequest("invalid manifest path"));
    }
    Ok(trimmed.to_string())
}
