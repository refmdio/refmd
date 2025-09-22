use uuid::Uuid;

use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::share_access_port::ShareAccessPort;

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
            let owns = access_repo
                .user_owns_document(doc_id, *uid)
                .await
                .unwrap_or(false);
            if owns {
                Capability::Edit
            } else {
                Capability::None
            }
        }
        Actor::ShareToken(t) => {
            // Resolve token target and then decide access when document matches token scope
            if let Ok(Some((share_id, perm, expires_at, shared_id, shared_type))) =
                shares_repo.resolve_share_by_token(t).await
            {
                // Check expiration
                if let Some(exp) = expires_at {
                    if exp < chrono::Utc::now() {
                        return Capability::None;
                    }
                }
                if shared_type != "folder" {
                    if shared_id == doc_id {
                        if perm == "edit" {
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
                        .get_materialized_permission(share_id, doc_id)
                        .await
                    {
                        Ok(Some(p)) => {
                            if p == "edit" {
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
