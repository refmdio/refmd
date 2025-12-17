use super::*;

impl StorageIngestService {
    pub(super) async fn permissions_for_event(
        &self,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<PermissionSet> {
        let set = permission_set_from_snapshot(&event.permission_snapshot);
        if !set.is_empty() {
            return Ok(set);
        }
        let mut candidates = Vec::new();
        if let Some(actor_id) = event.actor_id {
            candidates.push(("actor", actor_id, true));
        }
        let warn_on_user_miss = event.user_id != event.workspace_id;
        candidates.push(("user", event.user_id, warn_on_user_miss));
        for (source, user_id, warn_on_missing) in candidates {
            match self
                .permission_resolver
                .load_permission_set(event.workspace_id, user_id)
                .await
            {
                Ok(Some(resolved)) => {
                    info!(
                        workspace_id = %event.workspace_id,
                        user_id = %user_id,
                        source,
                        "storage_ingest_permissions_rehydrated"
                    );
                    return Ok(resolved);
                }
                Ok(None) => {
                    if warn_on_missing {
                        warn!(
                            workspace_id = %event.workspace_id,
                            user_id = %user_id,
                            source,
                            "storage_ingest_member_missing_for_permissions"
                        );
                    } else {
                        debug!(
                            workspace_id = %event.workspace_id,
                            user_id = %user_id,
                            source,
                            "storage_ingest_member_missing_for_permissions"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        workspace_id = %event.workspace_id,
                        user_id = %user_id,
                        source,
                        "storage_ingest_permission_resolve_failed"
                    );
                }
            }
        }
        warn!(
            workspace_id = %event.workspace_id,
            "storage_ingest_permissions_fallback_all"
        );
        Ok(PermissionSet::all())
    }
}
