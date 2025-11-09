use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::tags::TagItemDto;
use crate::application::ports::tag_repository::TagRepository;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::tags::list_tags::ListTags;

pub struct TagService {
    repo: Arc<dyn TagRepository>,
}

impl TagService {
    pub fn new(repo: Arc<dyn TagRepository>) -> Self {
        Self { repo }
    }

    pub async fn list(
        &self,
        user_id: Uuid,
        filter: Option<String>,
    ) -> Result<Vec<TagItemDto>, ServiceError> {
        let uc = ListTags {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, filter)
            .await
            .map_err(ServiceError::from)
    }
}
