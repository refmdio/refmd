use uuid::Uuid;

use crate::application::ports::user_repository::{UserRepository, UserRow};

pub struct GetMe<'a, R: UserRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: UserRepository + ?Sized> GetMe<'a, R> {
    pub async fn execute(&self, id: Uuid) -> anyhow::Result<Option<UserRow>> {
        self.repo.find_by_id(id).await
    }
}
