use uuid::Uuid;

use crate::application::dto::plugins::ExecResult;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::plugin_runtime::PluginRuntime;

pub struct ExecutePluginAction<'a, RT, PR, DR>
where
    RT: PluginRuntime + ?Sized,
    PR: PluginRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
{
    pub runtime: &'a RT,
    pub plugin_repo: &'a PR,
    pub document_repo: &'a DR,
}

impl<'a, RT, PR, DR> ExecutePluginAction<'a, RT, PR, DR>
where
    RT: PluginRuntime + ?Sized,
    PR: PluginRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        plugin: &str,
        action: &str,
        payload: Option<serde_json::Value>,
    ) -> anyhow::Result<Option<ExecResult>> {
        let payload = payload.unwrap_or(serde_json::Value::Null);
        let try_result = self
            .runtime
            .execute(Some(user_id), plugin, action, &payload)
            .await?;
        let Some(res) = try_result else {
            return Ok(None);
        };

        if !res.effects.is_empty() {
            match self
                .apply_server_effects(user_id, plugin, &res.effects)
                .await
            {
                Ok(passthrough) => {
                    return Ok(Some(ExecResult {
                        ok: true,
                        data: res.data,
                        effects: passthrough,
                        error: None,
                    }));
                }
                Err(err) => {
                    self.log_only(&res.effects);
                    return Err(err);
                }
            }
        }

        self.log_only(&res.effects);
        Ok(Some(res))
    }

    async fn apply_server_effects(
        &self,
        user_id: Uuid,
        plugin: &str,
        effects: &[serde_json::Value],
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut doc_id_created: Option<Uuid> = None;
        let mut passthrough: Vec<serde_json::Value> = Vec::new();

        for effect in effects {
            let Some(effect_type) = effect.get("type").and_then(|v| v.as_str()) else {
                passthrough.push(effect.clone());
                continue;
            };

            match effect_type {
                "log" => {
                    self.log_effect(effect);
                }
                "createDocument" => {
                    let title = effect
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Untitled");
                    let doc_type = effect
                        .get("docType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("document");
                    let parent_id = effect
                        .get("parentId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok());
                    let doc = self
                        .document_repo
                        .create_for_user(user_id, title, parent_id, doc_type)
                        .await?;
                    doc_id_created = Some(doc.id);
                }
                "putKv" => {
                    let Some(key) = effect.get("key").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let value = effect
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let doc_id = effect
                        .get("docId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .or(doc_id_created);
                    if let Some(did) = doc_id {
                        self.plugin_repo
                            .kv_set(plugin, "doc", Some(did), key, &value)
                            .await?;
                    }
                }
                "createRecord" => {
                    let Some(kind) = effect.get("kind").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let data = effect
                        .get("data")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let doc_id = effect
                        .get("docId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .or(doc_id_created);
                    if let Some(did) = doc_id {
                        let _ = self
                            .plugin_repo
                            .insert_record(plugin, "doc", did, kind, &data)
                            .await?;
                    }
                }
                "updateRecord" => {
                    if let Some(record_id) = effect
                        .get("recordId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        let patch = effect
                            .get("patch")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}));
                        let _ = self
                            .plugin_repo
                            .update_record_data(record_id, &patch)
                            .await?;
                    }
                }
                "deleteRecord" => {
                    if let Some(record_id) = effect
                        .get("recordId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        let _ = self.plugin_repo.delete_record(record_id).await?;
                    }
                }
                "navigate" => {
                    if let Some(doc_id) = doc_id_created {
                        if let Some(to) = effect.get("to").and_then(|v| v.as_str()) {
                            if to.contains(":createdDocId") {
                                let mut cloned = effect.clone();
                                if let Some(obj) = cloned.as_object_mut() {
                                    obj.insert(
                                        "to".into(),
                                        serde_json::Value::String(
                                            to.replace(":createdDocId", &doc_id.to_string()),
                                        ),
                                    );
                                }
                                passthrough.push(cloned);
                                continue;
                            }
                        }
                    }
                    passthrough.push(effect.clone());
                }
                _ => {
                    passthrough.push(effect.clone());
                }
            }
        }

        Ok(passthrough)
    }

    fn log_only(&self, effects: &[serde_json::Value]) {
        for effect in effects {
            if effect.get("type").and_then(|v| v.as_str()) == Some("log") {
                self.log_effect(effect);
            }
        }
    }

    fn log_effect(&self, effect: &serde_json::Value) {
        let level = effect
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let message = effect.get("message").and_then(|v| v.as_str()).unwrap_or("");
        match level {
            "debug" => tracing::debug!("[plugin] {}", message),
            "warn" | "warning" => tracing::warn!("[plugin] {}", message),
            "error" => tracing::error!("[plugin] {}", message),
            _ => tracing::info!("[plugin] {}", message),
        }
    }
}
