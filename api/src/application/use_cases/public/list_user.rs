use crate::application::ports::public_repository::PublicRepository;
#[derive(Debug, Clone)]
pub struct PublicDocumentSummaryDto {
    pub id: uuid::Uuid,
    pub title: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub published_at: chrono::DateTime<chrono::Utc>,
}

pub struct ListUserPublic<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> ListUserPublic<'a, R> {
    pub async fn execute(&self, owner_name: &str) -> anyhow::Result<Vec<PublicDocumentSummaryDto>> {
        let rows = self.repo.list_user_public_documents(owner_name).await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, title, updated_at, published_at)| PublicDocumentSummaryDto {
                    id,
                    title,
                    updated_at,
                    published_at,
                },
            )
            .collect())
    }
}
