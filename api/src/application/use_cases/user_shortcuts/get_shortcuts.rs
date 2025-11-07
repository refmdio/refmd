use uuid::Uuid;

use crate::application::ports::user_shortcut_repository::{
    UserShortcutProfile, UserShortcutRepository,
};

pub struct GetUserShortcuts<'a, R: UserShortcutRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> GetUserShortcuts<'a, R>
where
    R: UserShortcutRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Option<UserShortcutProfile>> {
        self.repo.get_by_user(user_id).await
    }
}
