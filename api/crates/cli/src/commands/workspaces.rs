use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use infrastructure::core::db::PgPool;

use crate::cli::WorkspaceCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: WorkspaceCommand) -> Result<()> {
    match cmd {
        WorkspaceCommand::List => list_workspaces(&deps.pool).await,
        WorkspaceCommand::Members { workspace_id } => {
            list_workspace_members(&deps.pool, workspace_id).await
        }
        WorkspaceCommand::Delete { workspace_id } => {
            match deps
                .workspace_service
                .delete_workspace(workspace_id)
                .await?
            {
                true => println!("deleted workspace {}", workspace_id),
                false => println!("workspace {} not found", workspace_id),
            }
            Ok(())
        }
    }
}

async fn list_workspaces(pool: &PgPool) -> Result<()> {
    let rows = sqlx::query(
        r#"SELECT id, name, slug, is_personal, created_at
           FROM workspaces
           ORDER BY created_at"#,
    )
    .fetch_all(pool)
    .await?;
    println!("{} workspace(s)", rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let name: String = row.get("name");
        let slug: String = row.get("slug");
        let is_personal: bool = row.get("is_personal");
        let created_at: DateTime<Utc> = row.get("created_at");
        println!(
            "{} | {} | slug={} | personal={} | created_at={}",
            id,
            name,
            slug,
            is_personal,
            created_at.to_rfc3339()
        );
    }
    Ok(())
}

async fn list_workspace_members(pool: &PgPool, workspace_id: Uuid) -> Result<()> {
    let rows = sqlx::query(
        r#"SELECT m.user_id, u.email, u.name, m.role_kind, m.system_role, m.custom_role_id, m.is_default, m.joined_at
           FROM workspace_members m
           JOIN users u ON u.id = m.user_id
           WHERE m.workspace_id = $1
           ORDER BY m.joined_at"#,
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await?;
    println!("{} member(s) for workspace {}", rows.len(), workspace_id);
    for row in rows {
        let user_id: Uuid = row.get("user_id");
        let email: String = row.get("email");
        let name: String = row.get("name");
        let role_kind: String = row.get("role_kind");
        let system_role: Option<String> = row.try_get("system_role").ok();
        let custom_role_id: Option<Uuid> = row.try_get("custom_role_id").ok();
        let is_default: bool = row.get("is_default");
        let joined_at: DateTime<Utc> = row.get("joined_at");
        println!(
            "{} | {} | {} | role_kind={} system_role={:?} custom_role_id={:?} default={} joined_at={}",
            user_id,
            email,
            name,
            role_kind,
            system_role,
            custom_role_id,
            is_default,
            joined_at.to_rfc3339()
        );
    }
    Ok(())
}
