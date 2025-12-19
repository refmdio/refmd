mod cli;

mod commands;
mod deps;
mod git_workspace;

use anyhow::Result;
use clap::Parser;

pub async fn run() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli::Cli {
        database_url,
        command,
    } = cli::Cli::parse();

    if let cli::Command::Openapi { command } = command {
        return commands::run_openapi(command);
    }

    let deps = deps::build(database_url).await?;
    commands::run(&deps, command).await
}
