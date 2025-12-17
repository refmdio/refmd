use std::sync::Arc;

use anyhow::Context;


use application::plugins::ports::plugin_asset_store::PluginAssetStore;
use application::plugins::ports::plugin_installer::PluginInstaller;
use application::plugins::ports::plugin_package_fetcher::PluginPackageFetcher;
use application::plugins::ports::plugin_runtime::PluginRuntime;
use crate::config::{Config, StorageBackend};
use infrastructure::plugins::filesystem_store::{
    FilesystemPluginStore, PluginExecutionLimits,
};

pub type PluginStack = (
    Arc<dyn PluginRuntime>,
    Arc<dyn PluginInstaller>,
    Arc<dyn PluginAssetStore>,
    Option<Arc<infrastructure::plugins::s3_store::S3BackedPluginStore>>,
    Arc<dyn PluginPackageFetcher>,
);

pub fn build_plugin_execution_limits(cfg: &Config) -> PluginExecutionLimits {
    let timeout = if cfg.plugin_timeout_secs == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(cfg.plugin_timeout_secs))
    };
    let memory_pages_raw = cfg.plugin_memory_max_mb.saturating_mul(16);
    let memory_max_pages = if memory_pages_raw == 0 {
        None
    } else {
        Some(memory_pages_raw.min(u32::MAX as u64) as u32)
    };
    let fuel_limit = cfg
        .plugin_fuel_limit
        .and_then(|limit| if limit == 0 { None } else { Some(limit) });
    PluginExecutionLimits::new(timeout, memory_max_pages, fuel_limit)
}

pub async fn build_plugin_stack(
    cfg: &Config,
    plugin_limits: PluginExecutionLimits,
) -> anyhow::Result<PluginStack> {
    let mut s3_plugin_store: Option<
        Arc<infrastructure::plugins::s3_store::S3BackedPluginStore>,
    > = None;

    let (plugin_runtime, plugin_installer, plugin_assets): (
        Arc<dyn PluginRuntime>,
        Arc<dyn PluginInstaller>,
        Arc<dyn PluginAssetStore>,
    ) = match cfg.storage_backend {
        StorageBackend::Filesystem => {
            let store = Arc::new(FilesystemPluginStore::new(&cfg.plugin_dir, plugin_limits)?);
            let runtime: Arc<dyn PluginRuntime> = store.clone();
            let installer: Arc<dyn PluginInstaller> = store.clone();
            let assets: Arc<dyn PluginAssetStore> = store.clone();
            (runtime, installer, assets)
        }
        StorageBackend::S3 => {
            let s3_store_cfg = infrastructure::plugins::s3_store::S3PluginStoreConfig {
                plugin_dir: cfg.plugin_dir.clone(),
                bucket: cfg
                    .s3_bucket
                    .clone()
                    .context("S3_BUCKET must be configured when using S3 storage backend")?,
                region: cfg.s3_region.clone(),
                endpoint: cfg.s3_endpoint.clone(),
                access_key: cfg.s3_access_key.clone(),
                secret_key: cfg.s3_secret_key.clone(),
                use_path_style: cfg.s3_use_path_style,
            };
            let store = Arc::new(
                infrastructure::plugins::s3_store::S3BackedPluginStore::new(
                    &s3_store_cfg,
                    plugin_limits,
                )
                .await?,
            );
            s3_plugin_store = Some(store.clone());
            let runtime: Arc<dyn PluginRuntime> = store.clone();
            let installer: Arc<dyn PluginInstaller> = store.clone();
            let assets: Arc<dyn PluginAssetStore> = store.clone();
            (runtime, installer, assets)
        }
    };
    let plugin_fetcher: Arc<dyn PluginPackageFetcher> = Arc::new(
        infrastructure::plugins::package_fetcher_reqwest::ReqwestPluginPackageFetcher::new(),
    );

    Ok((
        plugin_runtime,
        plugin_installer,
        plugin_assets,
        s3_plugin_store,
        plugin_fetcher,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_allow_zero_values() {
        let cfg = Config {
            plugin_timeout_secs: 0,
            plugin_memory_max_mb: 0,
            plugin_fuel_limit: Some(0),
            // irrelevant defaults
            api_port: 0,
            frontend_url: None,
            database_url: "".into(),
            jwt_secret_pem: "".into(),
            jwt_expires_secs: 0,
            session_refresh_ttl_secs: 0,
            session_refresh_remember_ttl_secs: 0,
            snapshot_interval_secs: 0,
            snapshot_keep_versions: 0,
            updates_keep_window: 0,
            storage_backend: StorageBackend::Filesystem,
            storage_root: "".into(),
            storage_monitor_enabled: false,
            storage_monitor_interval_secs: 0,
            storage_monitor_batch_size: 0,
            s3_endpoint: None,
            s3_bucket: None,
            s3_region: None,
            s3_access_key: None,
            s3_secret_key: None,
            s3_use_path_style: false,
            plugin_dir: "".into(),
            plugin_asset_sign_key: "".into(),
            plugin_asset_url_ttl_secs: 0,
            encryption_key: "".into(),
            upload_max_bytes: 0,
            public_base_url: None,
            is_production: false,
            cluster_mode: false,
            redis_url: None,
            redis_stream_prefix: "".into(),
            redis_min_message_lifetime_ms: 0,
            redis_task_debounce_ms: 0,
            redis_awareness_ttl_ms: 0,
            redis_stream_max_len: 0,
            snapshot_archive_interval_secs: 0,
            git_rebuild_enabled: false,
            git_rebuild_interval_secs: 0,
            google_oauth: None,
            github_oauth: None,
            oidc_oauth: None,
        };
        let limits = build_plugin_execution_limits(&cfg);
        assert_eq!(limits.timeout, None);
        assert_eq!(limits.memory_max_pages, None);
        assert_eq!(limits.fuel_limit, None);
    }
}
