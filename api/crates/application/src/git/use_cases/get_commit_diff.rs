use crate::core::dtos::TextDiffResult;
use crate::git::ports::git_workspace::GitWorkspacePort;
use uuid::Uuid;

pub struct GetCommitDiff<'a, W: GitWorkspacePort + ?Sized> {
    pub workspace: &'a W,
}

impl<'a, W: GitWorkspacePort + ?Sized> GetCommitDiff<'a, W> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        from: String,
        to: String,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        self.workspace
            .commit_diff(workspace_id, &from, &to)
            .await
            .map_err(Into::into)
    }
}
