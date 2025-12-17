use uuid::Uuid;

use crate::identity::dtos::UserShortcutProfileDto;
use crate::identity::ports::user_shortcuts::user_shortcut_repository::UserShortcutRepository;

pub struct GetUserShortcuts<'a, R: UserShortcutRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> GetUserShortcuts<'a, R>
where
    R: UserShortcutRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Option<UserShortcutProfileDto>> {
        let profile = self.repo.get_by_user(user_id).await?;
        Ok(profile.map(UserShortcutProfileDto::from))
    }
}
