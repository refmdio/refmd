use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use async_trait::async_trait;
use chrono::Utc;
use extism::{Manifest, Plugin, PluginBuilder, Wasm};
use once_cell::sync::Lazy;
use regex::Regex;
use semver::Version;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use tokio::{sync::RwLock, task};
use uuid::Uuid;

use application::plugins::dtos::ExecResult;
use application::plugins::ports::plugin_asset_store::{
    LatestGlobalManifest, PluginAssetPayload, PluginAssetStore, PluginAssetStoreScope,
};
use application::plugins::ports::plugin_installer::{
    InstalledPlugin, PluginInstallError, PluginInstaller,
};
use application::plugins::ports::plugin_runtime::PluginRuntime;

static PLUGIN_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid regex"));
static PLUGIN_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]+$").expect("valid regex"));

pub struct FilesystemPluginStore {
    root: PathBuf,
    plugin_cache: Arc<RwLock<HashMap<PathBuf, CachedPlugin>>>,
    limits: PluginExecutionLimits,
}

struct CachedPlugin {
    modified: SystemTime,
    plugin: Arc<Mutex<Plugin>>,
}

#[derive(Clone, Copy)]
pub struct PluginExecutionLimits {
    pub timeout: Option<Duration>,
    pub memory_max_pages: Option<u32>,
    pub fuel_limit: Option<u64>,
}

impl PluginExecutionLimits {
    pub const fn new(
        timeout: Option<Duration>,
        memory_max_pages: Option<u32>,
        fuel_limit: Option<u64>,
    ) -> Self {
        Self {
            timeout,
            memory_max_pages,
            fuel_limit,
        }
    }
}

impl Default for PluginExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
            memory_max_pages: Some(4096), // ~256 MiB
            fuel_limit: Some(50_000_000),
        }
    }
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

