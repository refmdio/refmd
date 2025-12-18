use anyhow::Result;
use uuid::Uuid;

use application::identity::ports::api_token_repository::ApiTokenRepository;
use application::identity::services::api_tokens::generate_api_token;
use infrastructure::identity::db::repositories::api_token_repository_sqlx::SqlxApiTokenRepository;

use crate::cli::TokenCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: TokenCommand) -> Result<()> {
    match cmd {
        TokenCommand::List { workspace_id } => list_tokens(&deps.api_tokens, workspace_id).await,
        TokenCommand::Create {
            workspace_id,
            owner_id,
            name,
        } => create_token(&deps.api_tokens, workspace_id, owner_id, name.as_deref()).await,
        TokenCommand::Revoke {
            workspace_id,
            token_id,
        } => {
            let revoked = deps.api_tokens.revoke(workspace_id, token_id).await?;
            if revoked {
                println!("revoked token {}", token_id);
            } else {
                println!("token {} not found or already revoked", token_id);
            }
            Ok(())
        }
    }
}

async fn list_tokens(repo: &SqlxApiTokenRepository, workspace_id: Uuid) -> Result<()> {
    let tokens = repo.list_active(workspace_id).await?;
    println!("{} token(s) in workspace {}", tokens.len(), workspace_id);
    for t in tokens {
        println!(
            "{} | name={} | owner={} | created_at={} | last_used={:?} | revoked={:?}",
            t.id,
            t.name,
            t.owner_id,
            t.created_at.to_rfc3339(),
            t.last_used_at.map(|d| d.to_rfc3339()),
            t.revoked_at.map(|d| d.to_rfc3339())
        );
    }
    Ok(())
}

async fn create_token(
    repo: &SqlxApiTokenRepository,
    workspace_id: Uuid,
    owner_id: Uuid,
    name: Option<&str>,
) -> Result<()> {
    let generated = generate_api_token()?;
    let stored = repo
        .create(
            workspace_id,
            owner_id,
            name.unwrap_or("cli-token"),
            &generated.token_hash,
            &generated.token_digest,
        )
        .await?;
    println!("created token {} name={}", stored.id, stored.name);
    println!("plaintext={}", generated.plaintext);
    println!("digest={}", generated.token_digest);
    Ok(())
}
