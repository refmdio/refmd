use crate::git::dtos::GitCommitInfo;
use crate::git::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetHistory<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetHistory<'a, W> {
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>> {
        self.workspace.history(workspace_id).await.map_err(Into::into)
    }
}
