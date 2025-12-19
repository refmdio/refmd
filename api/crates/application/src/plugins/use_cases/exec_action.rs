use std::collections::HashSet;

use uuid::Uuid;

use crate::core::services::access;
use crate::core::services::authorization::AuthorizationService;
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::document_repository::DocumentRepositoryError;
use crate::documents::use_cases::create_document::CreateDocument;
use crate::plugins::dtos::ExecResult;
use crate::plugins::ports::plugin_repository::PluginRepository;
use crate::plugins::ports::plugin_runtime::PluginRuntime;
use domain::access::permissions::{PERM_DOC_EDIT, PermissionSet};
use domain::documents::doc_type::DocumentType;
use domain::documents::title::Title;
use domain::plugins::policy;
use domain::plugins::scope::{PluginRecordScope, PluginScope};

enum PluginEffectError {
    PermissionDenied { permission: String },
    Other(anyhow::Error),
}

impl From<anyhow::Error> for PluginEffectError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

impl From<DocumentRepositoryError> for PluginEffectError {
    fn from(err: DocumentRepositoryError) -> Self {
        Self::Other(err.into())
    }
}

impl From<policy::PluginPolicyError> for PluginEffectError {
    fn from(err: policy::PluginPolicyError) -> Self {
        match err {
            policy::PluginPolicyError::PermissionDenied { permission } => {
                PluginEffectError::PermissionDenied { permission }
            }
        }
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
    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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
                    policy::ensure_plugin_permission(
                        permissions,
                        policy::PLUGIN_PERMISSION_DOC_WRITE,
                    )?;
                    policy::ensure_workspace_can_create_documents(workspace_permissions)?;
                    let title = effect
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Untitled");
                    let title = Title::from_user_input(title);
                    let doc_type_str = effect
                        .get("docType")
                        .and_then(|v| v.as_str())
                        .unwrap_or(DocumentType::Document.as_str());
                    let doc_type = DocumentType::try_from(doc_type_str).map_err(|_| {
                        PluginEffectError::Other(anyhow::anyhow!("invalid_document_type"))
                    })?;
                    let parent_id = effect
                        .get("parentId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok());
                    let parent_desired_path = if let Some(pid) = parent_id {
                        let meta = self
                            .document_repo
                            .get_meta_for_owner(pid, workspace_id)
                            .await
                            .map_err(PluginEffectError::from)?
                            .ok_or_else(|| {
                                PluginEffectError::Other(anyhow::anyhow!(
                                    "parent_document_not_found"
                                ))
                            })?;
                        if meta.archived_at.is_some() {
                            return Err(PluginEffectError::Other(anyhow::anyhow!(
                                "parent_document_archived"
                            )));
                        }
                        Some(meta.desired_path)
                    } else {
                        None
                    };
                    let mut repo = self.document_repo;
                    let mut uc = CreateDocument { repo: &mut repo };
                    let doc = uc
                        .execute(
                            workspace_id,
                            user_id,
                            &title,
                            parent_id,
                            parent_desired_path.as_ref(),
                            doc_type,
                            Some(plugin),
                        )
                        .await
                        .map_err(PluginEffectError::from)?;
                    doc_id_created = Some(doc.id());
                }
                "putKv" => {
                    policy::ensure_plugin_permission(
                        permissions,
                        policy::PLUGIN_PERMISSION_DOC_WRITE,
                    )?;
                    policy::ensure_workspace_can_edit_documents(workspace_permissions)?;
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
                            .kv_set(plugin, PluginScope::Doc, Some(did), key, &value)
                            .await
                            .map_err(PluginEffectError::from)?;
                    }
                }
                "createRecord" => {
                    policy::ensure_plugin_permission(
                        permissions,
                        policy::PLUGIN_PERMISSION_DOC_WRITE,
                    )?;
                    policy::ensure_workspace_can_edit_documents(workspace_permissions)?;
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
                            .insert_record(plugin, PluginRecordScope::Doc, did, kind, &data)
                            .await
                            .map_err(PluginEffectError::from)?;
                    }
                }
                "updateRecord" => {
                    policy::ensure_plugin_permission(
                        permissions,
                        policy::PLUGIN_PERMISSION_DOC_WRITE,
                    )?;
                    policy::ensure_workspace_can_edit_documents(workspace_permissions)?;
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
                            policy::ensure_record_owned_by_plugin(&rec.plugin, plugin)?;
                            if rec.scope != PluginRecordScope::Doc {
                                continue;
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
                    policy::ensure_plugin_permission(
                        permissions,
                        policy::PLUGIN_PERMISSION_DOC_WRITE,
                    )?;
                    policy::ensure_workspace_can_edit_documents(workspace_permissions)?;
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
                            policy::ensure_record_owned_by_plugin(&rec.plugin, plugin)?;
                            if rec.scope != PluginRecordScope::Doc {
                                continue;
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
                    if let Some(doc_id) = doc_id_created
                        && let Some(to) = effect.get("to").and_then(|v| v.as_str())
                        && to.contains(":createdDocId")
                    {
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
            policy::ensure_doc_id_within_allowed_scope(doc_id, allowed)?;
        }
        if Some(doc_id) == doc_id_created {
            return Ok(Some(doc_id));
        }
        let capability = self
            .authorization
            .resolve_document(actor, doc_id)
            .await
            .map_err(|err| PluginEffectError::Other(anyhow::Error::new(err)))?;
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
