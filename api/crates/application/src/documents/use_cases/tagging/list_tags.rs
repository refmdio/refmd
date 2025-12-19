use uuid::Uuid;

use crate::documents::dtos::TagItemDto;
use crate::documents::ports::tagging::tag_repository::TagRepository;

pub struct ListTags<'a, R: TagRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: TagRepository + ?Sized> ListTags<'a, R> {
    pub async fn execute(
        &self,
        owner_id: Uuid,
        filter: Option<String>,
    ) -> anyhow::Result<Vec<TagItemDto>> {
        let rows = self.repo.list_tags(owner_id, filter).await?;
        Ok(rows
            .into_iter()
            .map(|row| TagItemDto {
                name: row.name,
                count: row.count,
            })
            .collect())
    }
}
