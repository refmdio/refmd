use anyhow::Result;

use crate::cli::Command;
use crate::deps::Deps;

mod git;
mod jobs;
mod plugins;
mod shares;
mod tokens;
mod users;
mod workspaces;

pub(crate) async fn run(deps: &Deps, command: Command) -> Result<()> {
    match command {
        Command::Users { command } => users::handle(deps, command).await,
        Command::Jobs { command } => jobs::handle(deps, command).await,
        Command::Workspaces { command } => workspaces::handle(deps, command).await,
        Command::Git { command } => git::handle(deps, command).await,
        Command::Plugins { command } => plugins::handle(deps, command).await,
        Command::Tokens { command } => tokens::handle(deps, command).await,
        Command::Shares { command } => shares::handle(deps, command).await,
    }
}
