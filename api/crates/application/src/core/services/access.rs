use uuid::Uuid;

use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use domain::documents::access_policy;
use domain::documents::doc_type::DocumentType;

pub use domain::documents::access_policy::Capability;

#[derive(Debug, Clone)]
pub enum Actor {
    User(Uuid),
    ShareToken(String),
    Public,
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
            access_policy::capability_for_user_document(&access.permissions, access.is_archived)
        }
        Actor::ShareToken(t) => {
            // Resolve token target and then decide access when document matches token scope
            if let Ok(Some(ctx)) = shares_repo.resolve_share_by_token(t).await {
                let is_archived = access_repo
                    .is_document_archived(doc_id)
                    .await
                    .unwrap_or(false);
                let materialized_permission = if ctx.shared_type == DocumentType::Folder {
                    shares_repo
                        .get_materialized_permission(ctx.share_id, doc_id)
                        .await
                        .ok()
                        .flatten()
                } else {
                    None
                };
                access_policy::capability_for_share_token(
                    &ctx,
                    doc_id,
                    chrono::Utc::now(),
                    is_archived,
                    materialized_permission,
                )
            } else {
                Capability::None
            }
        }
        Actor::Public => {
            let is_public = access_repo
                .is_document_public(doc_id)
                .await
                .unwrap_or(false);
            // Public documents remain view-only even when archived.
            access_policy::capability_for_public_document(is_public)
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
