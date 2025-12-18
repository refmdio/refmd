use anyhow::Result;
use uuid::Uuid;

use application::documents::ports::sharing::shares_repository::SharesRepository;
use infrastructure::documents::db::repositories::shares_repository_sqlx::SqlxSharesRepository;

use crate::cli::ShareCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: ShareCommand) -> Result<()> {
    match cmd {
        ShareCommand::List {
            workspace_id,
            document_id,
        } => list_shares(&deps.shares_repo, workspace_id, document_id).await,
        ShareCommand::Revoke {
            workspace_id,
            token,
        } => {
            let removed = deps
                .shares_repo
                .delete_share(workspace_id, token.trim())
                .await?;
            if removed {
                println!("revoked share token {}", token.trim());
            } else {
                println!("share token {} not found", token.trim());
            }
            Ok(())
        }
    }
}

async fn list_shares(
    repo: &SqlxSharesRepository,
    workspace_id: Uuid,
    document_id: Uuid,
) -> Result<()> {
    let shares = repo.list_document_shares(workspace_id, document_id).await?;
    println!(
        "{} share(s) for document {} in workspace {}",
        shares.len(),
        document_id,
        workspace_id
    );
    for s in shares {
        println!(
            "{} | token={} | perm={} | expires_at={:?} | parent_share_id={:?} | created_at={}",
            s.id,
            s.token,
            s.permission,
            s.expires_at.map(|d| d.to_rfc3339()),
            s.parent_share_id,
            s.created_at.to_rfc3339()
        );
    }
    Ok(())
}
