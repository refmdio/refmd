use std::sync::Arc;

use uuid::Uuid;

use crate::documents::ports::sharing::shares_repository::SharesRepository;

mod browse;
mod crud;
mod guards;
mod materialize;
mod mounts;

pub struct ShareService {
    repo: Arc<dyn SharesRepository>,
}

pub struct ShareDocumentMeta {
    pub document_id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
}

impl ShareService {
    pub fn new(repo: Arc<dyn SharesRepository>) -> Self {
        Self { repo }
    }
}
