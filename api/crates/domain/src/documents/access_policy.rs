use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access::permissions::{PERM_DOC_EDIT, PERM_DOC_VIEW, PermissionSet};
use crate::documents::doc_type::DocumentType;
use crate::documents::share::{self, ShareContext, SharePermission};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    None,
    View,
    Edit,
}

pub fn capability_for_user_document(permissions: &PermissionSet, is_archived: bool) -> Capability {
    if !permissions.allows(PERM_DOC_VIEW) {
        return Capability::None;
    }
    if is_archived {
        Capability::View
    } else if permissions.allows(PERM_DOC_EDIT) {
        Capability::Edit
    } else {
        Capability::View
    }
}

pub fn capability_for_public_document(is_public: bool) -> Capability {
    if is_public {
        Capability::View
    } else {
        Capability::None
    }
}

pub fn capability_for_share_token(
    ctx: &ShareContext,
    doc_id: Uuid,
    now: DateTime<Utc>,
    is_doc_archived: bool,
    materialized_permission: Option<SharePermission>,
) -> Capability {
    if is_doc_archived {
        return Capability::None;
    }
    if share::is_expired(ctx.expires_at.as_ref(), now) {
        return Capability::None;
    }

    if ctx.shared_type == DocumentType::Folder {
        match materialized_permission {
            Some(p) => {
                if p.allows_edit() {
                    Capability::Edit
                } else {
                    Capability::View
                }
            }
            None => Capability::None,
        }
    } else if ctx.shared_id == doc_id {
        if ctx.permission.allows_edit() {
            Capability::Edit
        } else {
            Capability::View
        }
    } else {
        Capability::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::share::SharePermission;

    #[test]
    fn user_document_requires_view_and_archived_is_view_only() {
        let perms = PermissionSet::default();
        assert_eq!(
            capability_for_user_document(&perms, false),
            Capability::None
        );

        let perms = PermissionSet::from_slice(&[PERM_DOC_VIEW]);
        assert_eq!(
            capability_for_user_document(&perms, false),
            Capability::View
        );

        let perms = PermissionSet::from_slice(&[PERM_DOC_VIEW, PERM_DOC_EDIT]);
        assert_eq!(
            capability_for_user_document(&perms, false),
            Capability::Edit
        );
        assert_eq!(capability_for_user_document(&perms, true), Capability::View);
    }

    #[test]
    fn public_document_is_view_only_when_published() {
        assert_eq!(capability_for_public_document(false), Capability::None);
        assert_eq!(capability_for_public_document(true), Capability::View);
    }

    #[test]
    fn share_token_denies_archived_and_expired() {
        let now = Utc::now();
        let ctx = ShareContext {
            share_id: Uuid::new_v4(),
            permission: SharePermission::View,
            expires_at: Some(now),
            shared_id: Uuid::new_v4(),
            shared_type: DocumentType::Document,
            workspace_id: Uuid::new_v4(),
        };
        assert_eq!(
            capability_for_share_token(&ctx, ctx.shared_id, now, false, None),
            Capability::None
        );
        assert_eq!(
            capability_for_share_token(
                &ShareContext {
                    expires_at: None,
                    ..ctx
                },
                ctx.shared_id,
                now,
                true,
                None
            ),
            Capability::None
        );
    }

    #[test]
    fn share_token_document_grants_on_id_match() {
        let now = Utc::now();
        let doc_id = Uuid::new_v4();
        let ctx = ShareContext {
            share_id: Uuid::new_v4(),
            permission: SharePermission::Edit,
            expires_at: None,
            shared_id: doc_id,
            shared_type: DocumentType::Document,
            workspace_id: Uuid::new_v4(),
        };
        assert_eq!(
            capability_for_share_token(&ctx, doc_id, now, false, None),
            Capability::Edit
        );
        assert_eq!(
            capability_for_share_token(&ctx, Uuid::new_v4(), now, false, None),
            Capability::None
        );
    }

    #[test]
    fn share_token_folder_uses_materialized_permission() {
        let now = Utc::now();
        let ctx = ShareContext {
            share_id: Uuid::new_v4(),
            permission: SharePermission::View,
            expires_at: None,
            shared_id: Uuid::new_v4(),
            shared_type: DocumentType::Folder,
            workspace_id: Uuid::new_v4(),
        };
        assert_eq!(
            capability_for_share_token(&ctx, Uuid::new_v4(), now, false, None),
            Capability::None
        );
        assert_eq!(
            capability_for_share_token(
                &ctx,
                Uuid::new_v4(),
                now,
                false,
                Some(SharePermission::View)
            ),
            Capability::View
        );
        assert_eq!(
            capability_for_share_token(
                &ctx,
                Uuid::new_v4(),
                now,
                false,
                Some(SharePermission::Edit)
            ),
            Capability::Edit
        );
    }
}
