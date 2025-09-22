use crate::application::dto::git::DiffResult;
use crate::application::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetCommitDiff<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetCommitDiff<'a, W> {
    pub async fn execute(
        &self,
        user_id: Uuid,
        from: String,
        to: String,
    ) -> anyhow::Result<Vec<DiffResult>> {
        self.workspace.commit_diff(user_id, &from, &to).await
    }
}
