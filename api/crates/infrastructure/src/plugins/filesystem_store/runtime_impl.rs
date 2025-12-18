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

    async fn permissions(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let plugin_dir = self.locate_plugin_dir(user_id, plugin)?;
        let Some(plugin_dir) = plugin_dir else {
            return Ok(None);
        };

        let manifest_path = plugin_dir.join("plugin.json");
        let manifest_str = tokio::fs::read_to_string(&manifest_path)
            .await
            .with_context(|| format!("read plugin manifest at {}", manifest_path.display()))?;
        let manifest: JsonValue = serde_json::from_str(&manifest_str)
            .with_context(|| format!("parse plugin manifest at {}", manifest_path.display()))?;

        Ok(Some(Self::extract_permissions(&manifest)))
    }
}
