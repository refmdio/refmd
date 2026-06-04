use anyhow::Result;

use super::cli::Command;
use super::deps::Deps;

mod git;
mod jobs;
mod openapi;
mod plugins;
mod shares;
mod snapshots;
mod tokens;
mod users;
mod workspaces;

pub(crate) fn run_openapi(command: super::cli::OpenapiCommand) -> Result<()> {
    openapi::handle(command)
}

pub(crate) async fn run(deps: &Deps, command: Command) -> Result<()> {
    match command {
        Command::Users { command } => users::handle(deps, command).await,
        Command::Jobs { command } => jobs::handle(deps, command).await,
        Command::Workspaces { command } => workspaces::handle(deps, command).await,
        Command::Git { command } => git::handle(deps, command).await,
        Command::Plugins { command } => plugins::handle(deps, command).await,
        Command::Tokens { command } => tokens::handle(deps, command).await,
        Command::Shares { command } => shares::handle(deps, command).await,
        Command::Snapshots { command } => snapshots::handle(deps, command).await,
        Command::Openapi { command } => openapi::handle(command),
    }
}
