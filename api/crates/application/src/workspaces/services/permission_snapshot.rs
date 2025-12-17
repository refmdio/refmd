use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tracing::warn;

use domain::workspaces::permissions::PermissionSet;

pub fn permission_set_from_snapshot(snapshot: &[String]) -> PermissionSet {
    permission_set_from_snapshot_or_else(snapshot, PermissionSet::default)
}

pub fn permission_set_from_snapshot_or_else<F>(snapshot: &[String], fallback: F) -> PermissionSet
where
    F: FnOnce() -> PermissionSet,
{
    if snapshot.is_empty() {
        warn!("workspace_permission_snapshot_missing");
        fallback()
    } else {
        PermissionSet::from_strings(snapshot.iter().cloned())
    }
}

pub fn permission_set_from_snapshot_or_all(snapshot: &[String]) -> PermissionSet {
    permission_set_from_snapshot_or_else(snapshot, PermissionSet::all)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePermissionContext {
    pub workspace_id: Uuid,
    pub permission_snapshot: Vec<String>,
}

impl WorkspacePermissionContext {
    pub fn new(workspace_id: Uuid, permission_set: &PermissionSet) -> Self {
        Self {
            workspace_id,
            permission_snapshot: permission_set.to_vec(),
        }
    }

    pub fn from_snapshot(workspace_id: Uuid, snapshot: &[String]) -> Self {
        Self {
            workspace_id,
            permission_snapshot: snapshot.to_vec(),
        }
    }

    pub fn workspace_id(&self) -> Uuid {
        self.workspace_id
    }

    pub fn snapshot(&self) -> &[String] {
        &self.permission_snapshot
    }

    pub fn into_permission_set(self) -> PermissionSet {
        permission_set_from_snapshot(&self.permission_snapshot)
    }

    pub fn to_permission_set(&self) -> PermissionSet {
        permission_set_from_snapshot(&self.permission_snapshot)
    }
}
