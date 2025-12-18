#[path = "refmd/cli.rs"]
mod cli;

#[path = "refmd/commands/mod.rs"]
mod commands;

#[path = "refmd/deps.rs"]
mod deps;

#[path = "refmd/git_workspace.rs"]
mod git_workspace;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let Cli {
        database_url,
        command,
    } = Cli::parse();

    let deps = deps::build(database_url).await?;
    commands::run(&deps, command).await
}
