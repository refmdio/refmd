use uuid::Uuid;

use crate::core::services::errors::ServiceError;
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
) -> Result<Capability, ServiceError>
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    match actor {
        Actor::User(uid) => {
            let access = access_repo
                .resolve_user_document_access(doc_id, *uid)
                .await
                .map_err(ServiceError::from)?;
            let Some(access) = access else {
                return Ok(Capability::None);
            };
            Ok(access_policy::capability_for_user_document(
                &access.permissions,
                access.is_archived,
            ))
        }
        Actor::ShareToken(t) => {
            // Resolve token target and then decide access when document matches token scope
            let ctx = shares_repo
                .resolve_share_by_token(t)
                .await
                .map_err(ServiceError::from)?;
            let Some(ctx) = ctx else {
                return Ok(Capability::None);
            };
            let is_archived = access_repo
                .is_document_archived(doc_id)
                .await
                .map_err(ServiceError::from)?;
            let materialized_permission = if ctx.shared_type == DocumentType::Folder {
                shares_repo
                    .get_materialized_permission(ctx.share_id, doc_id)
                    .await
                    .map_err(ServiceError::from)?
            } else {
                None
            };
            Ok(access_policy::capability_for_share_token(
                &ctx,
                doc_id,
                chrono::Utc::now(),
                is_archived,
                materialized_permission,
            ))
        }
        Actor::Public => {
            let is_public = access_repo
                .is_document_public(doc_id)
                .await
                .map_err(ServiceError::from)?;
            // Public documents remain view-only even when archived.
            Ok(access_policy::capability_for_public_document(is_public))
        }
    }
}

pub async fn require_view<A, R>(
    access_repo: &A,
    shares_repo: &R,
    actor: &Actor,
    doc_id: Uuid,
) -> Result<Capability, ServiceError>
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    let cap = resolve_document(access_repo, shares_repo, actor, doc_id).await?;
    if cap >= Capability::View {
        Ok(cap)
    } else {
        Err(ServiceError::Forbidden)
    }
}

pub async fn require_edit<A, R>(
    access_repo: &A,
    shares_repo: &R,
    actor: &Actor,
    doc_id: Uuid,
) -> Result<(), ServiceError>
where
    A: AccessRepository + ?Sized,
    R: ShareAccessPort + ?Sized,
{
    let cap = resolve_document(access_repo, shares_repo, actor, doc_id).await?;
    if cap >= Capability::Edit {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}
