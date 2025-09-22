use crate::application::dto::git::DiffResult;
use crate::application::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetWorkingDiff<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetWorkingDiff<'a, W> {
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Vec<DiffResult>> {
        self.workspace.working_diff(user_id).await
    }
}
