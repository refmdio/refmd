use std::collections::HashSet;

use uuid::Uuid;

use crate::application::dto::plugins::ExecResult;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::plugin_runtime::PluginRuntime;
use crate::domain::workspaces::permissions::{PERM_DOC_CREATE, PERM_DOC_EDIT, PermissionSet};
use crate::{application::access, application::services::authorization::AuthorizationService};

const PERMISSION_DOC_WRITE: &str = "doc.write";

enum PluginEffectError {
    PermissionDenied { permission: String },
    Other(anyhow::Error),
}

impl From<anyhow::Error> for PluginEffectError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

pub struct ExecutePluginAction<'a, RT, PR, DR>
where
    RT: PluginRuntime + ?Sized,
    PR: PluginRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
{
    pub runtime: &'a RT,
    pub plugin_repo: &'a PR,
    pub document_repo: &'a DR,
    pub authorization: &'a AuthorizationService,
}

impl<'a, RT, PR, DR> ExecutePluginAction<'a, RT, PR, DR>
where
    RT: PluginRuntime + ?Sized,
    PR: PluginRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        workspace_permissions: &PermissionSet,
        plugin: &str,
        action: &str,
        payload: Option<serde_json::Value>,
        allowed_doc_id: Option<Uuid>,
        actor: &access::Actor,
    ) -> anyhow::Result<Option<ExecResult>> {
        let payload = payload.unwrap_or(serde_json::Value::Null);
        let runtime_scope = Some(workspace_id);
        let permissions = self
            .runtime
            .permissions(runtime_scope, plugin)
            .await?
            .unwrap_or_default()
            .into_iter()
            .collect::<HashSet<String>>();
        let try_result = self
            .runtime
            .execute(runtime_scope, plugin, action, &payload)
            .await?;
        let Some(res) = try_result else {
            return Ok(None);
        };

        if !res.effects.is_empty() {
            match self
                .apply_server_effects(
                    workspace_id,
                    user_id,
                    plugin,
                    &res.effects,
                    &permissions,
                    workspace_permissions,
                    allowed_doc_id,
                    actor,
                )
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
                Err(PluginEffectError::PermissionDenied { permission }) => {
                    self.log_only(&res.effects);
                    return Ok(Some(ExecResult {
                        ok: false,
                        data: None,
                        effects: vec![],
                        error: Some(serde_json::json!({
                            "code": "PERMISSION_DENIED",
                            "permission": permission,
                        })),
                    }));
                }
                Err(PluginEffectError::Other(err)) => {
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
        workspace_id: Uuid,
        user_id: Uuid,
        plugin: &str,
        effects: &[serde_json::Value],
        permissions: &HashSet<String>,
        workspace_permissions: &PermissionSet,
        allowed_doc_id: Option<Uuid>,
        actor: &access::Actor,
    ) -> Result<Vec<serde_json::Value>, PluginEffectError> {
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
                    self.ensure_permission(permissions, PERMISSION_DOC_WRITE)?;
                    if !workspace_permissions.allows(PERM_DOC_CREATE) {
                        return Err(PluginEffectError::PermissionDenied {
                            permission: PERM_DOC_CREATE.to_string(),
                        });
                    }
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
                        .create_for_user(
                            workspace_id,
                            user_id,
                            title,
                            parent_id,
                            doc_type,
                            Some(plugin),
                        )
                        .await
                        .map_err(PluginEffectError::from)?;
                    doc_id_created = Some(doc.id);
                }
                "putKv" => {
                    self.ensure_permission(permissions, PERMISSION_DOC_WRITE)?;
                    if !workspace_permissions.allows(PERM_DOC_EDIT) {
                        return Err(PluginEffectError::PermissionDenied {
                            permission: PERM_DOC_EDIT.to_string(),
                        });
                    }
                    let Some(key) = effect.get("key").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let value = effect
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let doc_id = self
                        .validate_doc_scope(
                            workspace_id,
                            effect
                                .get("docId")
                                .and_then(|v| v.as_str())
                                .and_then(|s| Uuid::parse_str(s).ok())
                                .or(doc_id_created),
                            allowed_doc_id,
                            doc_id_created,
                            actor,
                            true,
                        )
                        .await?;
                    if let Some(did) = doc_id {
                        self.plugin_repo
                            .kv_set(plugin, "doc", Some(did), key, &value)
                            .await
                            .map_err(PluginEffectError::from)?;
                    }
                }
                "createRecord" => {
                    self.ensure_permission(permissions, PERMISSION_DOC_WRITE)?;
                    if !workspace_permissions.allows(PERM_DOC_EDIT) {
                        return Err(PluginEffectError::PermissionDenied {
                            permission: PERM_DOC_EDIT.to_string(),
                        });
                    }
                    let Some(kind) = effect.get("kind").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let data = effect
                        .get("data")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let doc_id = self
                        .validate_doc_scope(
                            workspace_id,
                            effect
                                .get("docId")
                                .and_then(|v| v.as_str())
                                .and_then(|s| Uuid::parse_str(s).ok())
                                .or(doc_id_created),
                            allowed_doc_id,
                            doc_id_created,
                            actor,
                            true,
                        )
                        .await?;
                    if let Some(did) = doc_id {
                        let _ = self
                            .plugin_repo
                            .insert_record(plugin, "doc", did, kind, &data)
                            .await
                            .map_err(PluginEffectError::from)?;
                    }
                }
                "updateRecord" => {
                    self.ensure_permission(permissions, PERMISSION_DOC_WRITE)?;
                    if !workspace_permissions.allows(PERM_DOC_EDIT) {
                        return Err(PluginEffectError::PermissionDenied {
                            permission: PERM_DOC_EDIT.to_string(),
                        });
                    }
                    if let Some(record_id) = effect
                        .get("recordId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        if let Some(rec) = self
                            .plugin_repo
                            .get_record(record_id)
                            .await
                            .map_err(PluginEffectError::from)?
                        {
                            if rec.plugin != plugin {
                                return Err(PluginEffectError::PermissionDenied {
                                    permission: PERM_DOC_EDIT.to_string(),
                                });
                            }
                            self.validate_doc_scope(
                                workspace_id,
                                Some(rec.scope_id),
                                allowed_doc_id,
                                doc_id_created,
                                actor,
                                true,
                            )
                            .await?;
                        }
                        let patch = effect
                            .get("patch")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}));
                        let _ = self
                            .plugin_repo
                            .update_record_data(record_id, &patch)
                            .await
                            .map_err(PluginEffectError::from)?;
                    }
                }
                "deleteRecord" => {
                    self.ensure_permission(permissions, PERMISSION_DOC_WRITE)?;
                    if !workspace_permissions.allows(PERM_DOC_EDIT) {
                        return Err(PluginEffectError::PermissionDenied {
                            permission: PERM_DOC_EDIT.to_string(),
                        });
                    }
                    if let Some(record_id) = effect
                        .get("recordId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        if let Some(rec) = self
                            .plugin_repo
                            .get_record(record_id)
                            .await
                            .map_err(PluginEffectError::from)?
                        {
                            if rec.plugin != plugin {
                                return Err(PluginEffectError::PermissionDenied {
                                    permission: PERM_DOC_EDIT.to_string(),
                                });
                            }
                            self.validate_doc_scope(
                                workspace_id,
                                Some(rec.scope_id),
                                allowed_doc_id,
                                doc_id_created,
                                actor,
                                true,
                            )
                            .await?;
                        }
                        let _ = self
                            .plugin_repo
                            .delete_record(record_id)
                            .await
                            .map_err(PluginEffectError::from)?;
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

    async fn validate_doc_scope(
        &self,
        _workspace_id: Uuid,
        mut doc_id: Option<Uuid>,
        allowed_doc_id: Option<Uuid>,
        doc_id_created: Option<Uuid>,
        actor: &access::Actor,
        require_edit: bool,
    ) -> Result<Option<Uuid>, PluginEffectError> {
        // When doc_id is omitted, fall back to the explicitly allowed doc for share tokens.
        doc_id = doc_id.or(allowed_doc_id);

        let Some(doc_id) = doc_id else {
            return Ok(None);
        };
        if let Some(allowed) = allowed_doc_id {
            if doc_id != allowed {
                return Err(PluginEffectError::PermissionDenied {
                    permission: PERM_DOC_EDIT.to_string(),
                });
            }
        }
        if Some(doc_id) == doc_id_created {
            return Ok(Some(doc_id));
        }
        let capability = self.authorization.resolve_document(actor, doc_id).await;
        let has_access = if require_edit {
            capability >= access::Capability::Edit
        } else {
            capability >= access::Capability::View
        };
        if has_access {
            Ok(Some(doc_id))
        } else {
            Err(PluginEffectError::PermissionDenied {
                permission: PERM_DOC_EDIT.to_string(),
            })
        }
    }

    fn ensure_permission(
        &self,
        permissions: &HashSet<String>,
        permission: &str,
    ) -> Result<(), PluginEffectError> {
        if permissions.iter().any(|p| p == permission) {
            Ok(())
        } else {
            Err(PluginEffectError::PermissionDenied {
                permission: permission.to_string(),
            })
        }
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
