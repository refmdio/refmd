use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PERM_DOC_VIEW: &str = "doc:view";
pub const PERM_DOC_EDIT: &str = "doc:edit";
pub const PERM_DOC_CREATE: &str = "doc:create";
pub const PERM_DOC_ARCHIVE: &str = "doc:archive";
pub const PERM_DOC_DELETE: &str = "doc:delete";
pub const PERM_DOC_MOVE: &str = "doc:move";
pub const PERM_FOLDER_CREATE: &str = "folder:create";
pub const PERM_FOLDER_DELETE: &str = "folder:delete";
pub const PERM_FILE_UPLOAD: &str = "file:upload";
pub const PERM_FILE_DELETE: &str = "file:delete";
pub const PERM_SHARE_CREATE: &str = "share:create";
pub const PERM_SHARE_DELETE: &str = "share:delete";
pub const PERM_PUBLIC_PUBLISH: &str = "public:publish";
pub const PERM_PUBLIC_UNPUBLISH: &str = "public:unpublish";
pub const PERM_MEMBER_VIEW: &str = "member:view";
pub const PERM_MEMBER_INVITE: &str = "member:invite";
pub const PERM_MEMBER_UPDATE_ROLE: &str = "member:update_role";
pub const PERM_MEMBER_REMOVE: &str = "member:remove";
pub const PERM_WORKSPACE_UPDATE: &str = "workspace:update_settings";
pub const PERM_WORKSPACE_DELETE: &str = "workspace:delete";
pub const PERM_PLUGIN_INSTALL: &str = "plugin:install";
pub const PERM_PLUGIN_UNINSTALL: &str = "plugin:uninstall";
pub const PERM_PLUGIN_RUN: &str = "plugin:run";
pub const PERM_GIT_INIT: &str = "git:init";
pub const PERM_GIT_SYNC: &str = "git:sync";
pub const PERM_GIT_CONFIGURE: &str = "git:configure";
pub const PERM_SHORTCUT_UPDATE: &str = "shortcut:update";
pub const PERM_API_TOKEN_MANAGE: &str = "api_token:manage";

const ALL_PERMISSIONS: &[&str] = &[
    PERM_DOC_VIEW,
    PERM_DOC_EDIT,
    PERM_DOC_CREATE,
    PERM_DOC_ARCHIVE,
    PERM_DOC_DELETE,
    PERM_DOC_MOVE,
    PERM_FOLDER_CREATE,
    PERM_FOLDER_DELETE,
    PERM_FILE_UPLOAD,
    PERM_FILE_DELETE,
    PERM_SHARE_CREATE,
    PERM_SHARE_DELETE,
    PERM_PUBLIC_PUBLISH,
    PERM_PUBLIC_UNPUBLISH,
    PERM_MEMBER_VIEW,
    PERM_MEMBER_INVITE,
    PERM_MEMBER_UPDATE_ROLE,
    PERM_MEMBER_REMOVE,
    PERM_WORKSPACE_UPDATE,
    PERM_WORKSPACE_DELETE,
    PERM_PLUGIN_INSTALL,
    PERM_PLUGIN_UNINSTALL,
    PERM_PLUGIN_RUN,
    PERM_GIT_INIT,
    PERM_GIT_SYNC,
    PERM_GIT_CONFIGURE,
    PERM_SHORTCUT_UPDATE,
    PERM_API_TOKEN_MANAGE,
];

#[derive(Debug, Clone, Default)]
pub struct PermissionSet {
    allowed: BTreeSet<String>,
}

impl PermissionSet {
    pub fn allows(&self, permission: &str) -> bool {
        self.allowed.contains(permission)
    }

    pub fn insert(&mut self, permission: impl Into<String>) {
        self.allowed.insert(permission.into());
    }

    pub fn remove(&mut self, permission: &str) {
        self.allowed.remove(permission);
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.allowed.iter()
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.allowed.iter().cloned().collect()
    }

    pub fn union(mut self, other: PermissionSet) -> Self {
        for perm in other.allowed {
            self.allowed.insert(perm);
        }
        self
    }

    pub fn from_slice(perms: &[&str]) -> Self {
        let mut set = PermissionSet::default();
        for perm in perms {
            set.allowed.insert(perm.to_string());
        }
        set
    }

    pub fn from_strings<I, S>(perms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = PermissionSet::default();
        for perm in perms {
            set.allowed.insert(perm.into());
        }
        set
    }

    pub fn all() -> Self {
        Self::from_slice(ALL_PERMISSIONS)
    }
}

pub fn system_role_permissions(role: &str) -> PermissionSet {
    match role {
        "owner" => PermissionSet::all(),
        "admin" => {
            let mut base = PermissionSet::all();
            base.remove(PERM_WORKSPACE_DELETE);
            base
        }
        "editor" => PermissionSet::from_slice(&[
            PERM_DOC_VIEW,
            PERM_DOC_EDIT,
            PERM_DOC_CREATE,
            PERM_DOC_ARCHIVE,
            PERM_DOC_DELETE,
            PERM_DOC_MOVE,
            PERM_FOLDER_CREATE,
            PERM_FOLDER_DELETE,
            PERM_FILE_UPLOAD,
            PERM_FILE_DELETE,
            PERM_SHARE_CREATE,
            PERM_SHARE_DELETE,
            PERM_PUBLIC_PUBLISH,
            PERM_PUBLIC_UNPUBLISH,
            PERM_PLUGIN_RUN,
            PERM_PLUGIN_INSTALL,
            PERM_PLUGIN_UNINSTALL,
            PERM_GIT_INIT,
            PERM_GIT_SYNC,
            PERM_GIT_CONFIGURE,
            PERM_SHORTCUT_UPDATE,
            PERM_API_TOKEN_MANAGE,
        ]),
        "viewer" => PermissionSet::from_slice(&[PERM_DOC_VIEW]),
        _ => PermissionSet::default(),
    }
}

pub fn apply_custom_overrides<I, S>(mut base: PermissionSet, overrides: I) -> PermissionSet
where
    I: IntoIterator<Item = (S, bool)>,
    S: AsRef<str>,
{
    for (permission, allowed) in overrides {
        let key = permission.as_ref();
        if allowed {
            base.insert(key.to_string());
        } else {
            base.remove(key);
        }
    }
    base
}

pub fn permission_set_from_snapshot(snapshot: &[String]) -> PermissionSet {
    if snapshot.is_empty() {
        PermissionSet::all()
    } else {
        PermissionSet::from_strings(snapshot.iter().cloned())
    }
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
