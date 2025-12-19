impl FilesystemPluginStore {
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

    fn extract_permissions(manifest: &JsonValue) -> Vec<String> {
        manifest
            .get("permissions")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default()
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
        let limits = self.limits;
        let plugin = task::spawn_blocking(move || -> anyhow::Result<Plugin> {
            let mut manifest = Manifest::new([Wasm::data(wasm_bytes)]);
            if let Some(timeout) = limits.timeout {
                manifest = manifest.with_timeout(timeout);
            }
            if let Some(memory_max) = limits.memory_max_pages {
                manifest = manifest.with_memory_max(memory_max);
            }
            let builder = PluginBuilder::new(manifest).with_wasi(true);
            let builder = if let Some(fuel_limit) = limits.fuel_limit {
                builder.with_fuel_limit(fuel_limit)
            } else {
                builder
            };
            builder.build().context("create plugin")
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
}
