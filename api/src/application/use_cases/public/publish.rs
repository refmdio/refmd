use uuid::Uuid;

use crate::application::ports::public_repository::PublicRepository;
#[derive(Debug, Clone)]
pub struct PublishResponseDto {
    pub slug: String,
    pub public_url: String,
}
fn sanitize_title_local(name: &str) -> String {
    let mut s = name.trim().to_string();
    let invalid = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    for ch in invalid {
        s = s.replace(ch, "-");
    }
    s = s.replace(' ', "_");
    if s.len() > 100 {
        s.truncate(100);
    }
    s
}

pub struct PublishDocument<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> PublishDocument<'a, R> {
    pub async fn execute(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<PublishResponseDto>> {
        let (title, owner_name) = match self
            .repo
            .ensure_ownership_and_owner_name(doc_id, owner_id)
            .await?
        {
            Some(v) => v,
            None => return Ok(None),
        };
        let mut base_slug = sanitize_title_local(&title);
        if base_slug.is_empty() {
            base_slug = doc_id.to_string();
        }
        let mut slug = format!("{}-{}", base_slug, &doc_id.to_string()[..8]);
        let mut i = 1;
        while self.repo.slug_exists(&slug).await? {
            slug = format!("{}-{}-{}", base_slug, &doc_id.to_string()[..8], i);
            i += 1;
        }
        self.repo.upsert_public_document(doc_id, &slug).await?;
        let public_url = format!("/u/{}/{}", owner_name, doc_id);
        Ok(Some(PublishResponseDto { slug, public_url }))
    }
}
