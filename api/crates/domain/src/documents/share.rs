use chrono::{DateTime, Utc};
use std::fmt;
use uuid::Uuid;

use crate::documents::doc_type::DocumentType;

pub const SHARE_PERMISSION_VIEW: &str = "view";
pub const SHARE_PERMISSION_EDIT: &str = "edit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePermission {
    View,
    Edit,
}

impl SharePermission {
    pub fn from_str(permission: &str) -> Option<Self> {
        match normalize_permission(permission)? {
            SHARE_PERMISSION_VIEW => Some(SharePermission::View),
            SHARE_PERMISSION_EDIT => Some(SharePermission::Edit),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SharePermission::View => SHARE_PERMISSION_VIEW,
            SharePermission::Edit => SHARE_PERMISSION_EDIT,
        }
    }

    pub fn allows_edit(self) -> bool {
        matches!(self, SharePermission::Edit)
    }
}

impl fmt::Display for SharePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ShareContext {
    pub share_id: Uuid,
    pub permission: SharePermission,
    pub expires_at: Option<DateTime<Utc>>,
    pub shared_id: Uuid,
    pub shared_type: DocumentType,
    pub workspace_id: Uuid,
}

pub fn normalize_permission(permission: &str) -> Option<&'static str> {
    match permission.trim() {
        SHARE_PERMISSION_VIEW => Some(SHARE_PERMISSION_VIEW),
        SHARE_PERMISSION_EDIT => Some(SHARE_PERMISSION_EDIT),
        _ => None,
    }
}

pub fn is_edit_permission(permission: &str) -> bool {
    permission.trim() == SHARE_PERMISSION_EDIT
}

pub fn is_expired(expires_at: Option<&DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    matches!(expires_at, Some(exp) if *exp <= now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_permission_accepts_view_and_edit() {
        assert_eq!(normalize_permission("view"), Some(SHARE_PERMISSION_VIEW));
        assert_eq!(normalize_permission("edit"), Some(SHARE_PERMISSION_EDIT));
        assert_eq!(normalize_permission(" view "), Some(SHARE_PERMISSION_VIEW));
    }

    #[test]
    fn normalize_permission_rejects_unknown() {
        assert_eq!(normalize_permission(""), None);
        assert_eq!(normalize_permission("owner"), None);
    }

    #[test]
    fn share_permission_parses_and_formats() {
        assert_eq!(
            SharePermission::from_str("view"),
            Some(SharePermission::View)
        );
        assert_eq!(
            SharePermission::from_str("edit"),
            Some(SharePermission::Edit)
        );
        assert_eq!(SharePermission::from_str("nope"), None);
        assert_eq!(SharePermission::Edit.as_str(), SHARE_PERMISSION_EDIT);
        assert!(SharePermission::Edit.allows_edit());
        assert!(!SharePermission::View.allows_edit());
    }

    #[test]
    fn none_is_not_expired() {
        assert!(!is_expired(None, Utc::now()));
    }

    #[test]
    fn past_is_expired() {
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(1);
        assert!(is_expired(Some(&past), now));
    }

    #[test]
    fn future_is_not_expired() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(1);
        assert!(!is_expired(Some(&future), now));
    }

    #[test]
    fn exactly_now_is_expired() {
        let now = Utc::now();
        assert!(is_expired(Some(&now), now));
    }

    #[test]
    fn is_edit_permission_trims_and_is_strict() {
        assert!(is_edit_permission(" edit "));
        assert!(!is_edit_permission("view"));
        assert!(!is_edit_permission("EDIT"));
    }
}
