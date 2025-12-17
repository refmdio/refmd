use uuid::Uuid;

use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use domain::documents::doc_type::DocumentType;
use domain::documents::share;
use domain::workspaces::permissions::{PERM_DOC_EDIT, PERM_DOC_VIEW};

#[derive(Debug, Clone)]
pub enum Actor {
    User(Uuid),
    ShareToken(String),
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    None,
    View,
    Edit,
}

// Presentation layer is responsible for building Actor from HTTP inputs.
// This module intentionally avoids depending on presentation types.

pub async fn resolve_document<A, R>(
    access_repo: &A,
    shares_repo: &R,
    actor: &Actor,
    doc_id: Uuid,
) -> Capability
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    match actor {
        Actor::User(uid) => {
            let access = match access_repo.resolve_user_document_access(doc_id, *uid).await {
                Ok(Some(access)) => access,
                _ => return Capability::None,
            };
            if !access.permissions.allows(PERM_DOC_VIEW) {
                return Capability::None;
            }
            if access.is_archived {
                Capability::View
            } else if access.permissions.allows(PERM_DOC_EDIT) {
                Capability::Edit
            } else {
                Capability::View
            }
        }
        Actor::ShareToken(t) => {
            // Resolve token target and then decide access when document matches token scope
            if let Ok(Some(ctx)) = shares_repo.resolve_share_by_token(t).await {
                if access_repo
                    .is_document_archived(doc_id)
                    .await
                    .unwrap_or(false)
                {
                    return Capability::None;
                }
                // Check expiration
                if share::is_expired(ctx.expires_at.as_ref(), chrono::Utc::now()) {
                    return Capability::None;
                }
                if ctx.shared_type != DocumentType::Folder {
                    if ctx.shared_id == doc_id {
                        if ctx.permission.allows_edit() {
                            Capability::Edit
                        } else {
                            Capability::View
                        }
                    } else {
                        Capability::None
                    }
                } else {
                    // Need a materialized child share for this doc
                    match shares_repo
                        .get_materialized_permission(ctx.share_id, doc_id)
                        .await
                    {
                        Ok(Some(p)) => {
                            if p.allows_edit() {
                                Capability::Edit
                            } else {
                                Capability::View
                            }
                        }
                        _ => Capability::None,
                    }
                }
            } else {
                Capability::None
            }
        }
        Actor::Public => {
            let is_pub = access_repo
                .is_document_public(doc_id)
                .await
                .unwrap_or(false);
            if is_pub {
                // Public documents remain view-only even when archived.
                Capability::View
            } else {
                Capability::None
            }
        }
    }
}

pub async fn require_view<A, R>(
    access_repo: &A,
    shares_repo: &R,
    actor: &Actor,
    doc_id: Uuid,
) -> anyhow::Result<Capability>
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    let cap = resolve_document(access_repo, shares_repo, actor, doc_id).await;
    if cap >= Capability::View {
        Ok(cap)
    } else {
        anyhow::bail!("unauthorized")
    }
}

pub async fn require_edit<A, R>(
    access_repo: &A,
    shares_repo: &R,
    actor: &Actor,
    doc_id: Uuid,
) -> anyhow::Result<()>
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    let cap = resolve_document(access_repo, shares_repo, actor, doc_id).await;
    if cap >= Capability::Edit {
        Ok(())
    } else {
        anyhow::bail!("forbidden")
    }
}
