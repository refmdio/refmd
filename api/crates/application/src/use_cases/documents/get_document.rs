use uuid::Uuid;

use crate::access::{self, Actor, Capability};
use crate::ports::access_repository::AccessRepository;
use crate::ports::document_repository::DocumentRepository;
use crate::ports::share_access_port::ShareAccessPort;
use domain::documents::document::Document as DomainDocument;

pub struct GetDocument<'a, R, S, A>
where
    R: DocumentRepository + ?Sized,
    S: ShareAccessPort + ?Sized,
    A: AccessRepository + ?Sized,
{
    pub repo: &'a R,
    pub shares: &'a S,
    pub access: &'a A,
}

impl<'a, R, S, A> GetDocument<'a, R, S, A>
where
    R: DocumentRepository + ?Sized,
    S: ShareAccessPort + ?Sized,
    A: AccessRepository + ?Sized,
{
    pub async fn execute(&self, actor: &Actor, id: Uuid) -> anyhow::Result<Option<DomainDocument>> {
        // Enforce view permission using existing access policy
        let cap = access::resolve_document(self.access, self.shares, actor, id).await;
        if cap < Capability::View {
            return Ok(None);
        }
        self.repo.get_by_id(id).await
    }
}
