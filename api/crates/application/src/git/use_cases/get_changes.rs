use crate::git::dtos::GitChangeItem;
use crate::git::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetChanges<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetChanges<'a, W> {
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>> {
        self.workspace.list_changes(workspace_id).await
    }
}
