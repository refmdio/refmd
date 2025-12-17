use crate::core::dtos::TextDiffResult;
use crate::git::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetWorkingDiff<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetWorkingDiff<'a, W> {
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<Vec<TextDiffResult>> {
        self.workspace.working_diff(workspace_id).await
    }
}
