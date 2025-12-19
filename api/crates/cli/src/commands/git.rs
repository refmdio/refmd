use anyhow::Result;

use application::git::ports::git_workspace::GitWorkspacePort;
use bootstrap::application;

use crate::cli::GitCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: GitCommand) -> Result<()> {
    match cmd {
        GitCommand::Status { workspace_id } => {
            let status = deps.git_workspace.status(workspace_id).await?;
            println!(
                "initialized={} branch={:?} uncommitted_changes={} untracked_files={}",
                status.repository_initialized,
                status.current_branch,
                status.uncommitted_changes,
                status.untracked_files
            );
            Ok(())
        }
        GitCommand::Changes { workspace_id } => {
            let changes = deps.git_workspace.list_changes(workspace_id).await?;
            println!("{} change(s)", changes.len());
            for c in changes {
                println!("{} {}", c.status, c.path);
            }
            Ok(())
        }
        GitCommand::Remove { workspace_id } => {
            deps.git_workspace.remove_repository(workspace_id).await?;
            println!("removed git workspace {}", workspace_id);
            Ok(())
        }
    }
}
