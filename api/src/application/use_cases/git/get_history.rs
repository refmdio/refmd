use crate::application::dto::git::GitCommitInfo;
use crate::application::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetHistory<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetHistory<'a, W> {
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>> {
        self.workspace.history(user_id).await
    }
}
