use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use bootstrap::{application, infrastructure};

use application::identity::ports::secret_hasher::SecretHasher;
use application::identity::ports::user_session_repository::UserSessionRepository;
use application::identity::use_cases::auth::delete_account::DeleteAccount;
use application::identity::use_cases::auth::register::{Register, RegisterRequest};
use application::workspaces::services::WorkspaceServiceFacade;
use infrastructure::core::db::PgPool;
use infrastructure::identity::crypto::Argon2SecretHasher;
use infrastructure::identity::db::repositories::user_repository_sqlx::SqlxUserRepository;
use infrastructure::identity::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository;

use crate::cli::UserCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: UserCommand) -> Result<()> {
    let hasher = Argon2SecretHasher;
    match cmd {
        UserCommand::List => list_users(&deps.pool).await,
        UserCommand::Create {
            email,
            name,
            password,
            user_id,
        } => {
            create_user(
                &deps.user_repo,
                deps.workspace_service.as_ref(),
                &hasher,
                email,
                name,
                password,
                user_id,
            )
            .await
        }
        UserCommand::SetPassword {
            user_id,
            password,
            revoke_sessions,
        } => {
            set_password(
                &deps.pool,
                &deps.session_repo,
                &hasher,
                user_id,
                password,
                revoke_sessions,
            )
            .await
        }
        UserCommand::Delete { user_id } => delete_user(deps, user_id).await,
        UserCommand::Sessions { user_id } => list_sessions(&deps.session_repo, user_id).await,
        UserCommand::RevokeSessions { user_id } => {
            deps.session_repo.revoke_all_for_user(user_id).await?;
            println!("revoked sessions for user {user_id}");
            Ok(())
        }
    }
}

async fn list_users(pool: &PgPool) -> Result<()> {
    let rows = sqlx::query(
        r#"SELECT id, email, name, default_workspace_id, created_at
            FROM users
            ORDER BY created_at"#,
    )
    .fetch_all(pool)
    .await?;

    println!("{} user(s)", rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let email: String = row.get("email");
        let name: String = row.get("name");
        let workspace_id: Uuid = row.get("default_workspace_id");
        let created_at: DateTime<Utc> = row.get("created_at");
        println!(
            "{id} | {email} | {name} | default_ws={workspace_id} | created_at={}",
            created_at.to_rfc3339()
        );
    }
    Ok(())
}

async fn list_sessions(repo: &SqlxUserSessionRepository, user_id: Uuid) -> Result<()> {
    let sessions = repo.list_for_user(user_id).await?;
    println!("{} session(s) for user {}", sessions.len(), user_id);
    for s in sessions {
        println!(
            "{} | workspace={} | remember={} | last_seen={} | created_at={} | revoked_at={}",
            s.id,
            s.workspace_id,
            s.remember_me,
            s.last_seen_at.to_rfc3339(),
            s.created_at.to_rfc3339(),
            s.revoked_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

async fn create_user(
    user_repo: &SqlxUserRepository,
    workspace_service: &dyn WorkspaceServiceFacade,
    hasher: &dyn SecretHasher,
    email: String,
    name: String,
    password: String,
    explicit_user_id: Option<Uuid>,
) -> Result<()> {
    let normalized_email = email.trim();
    ensure!(!normalized_email.is_empty(), "email must not be empty");
    ensure!(!password.trim().is_empty(), "password must not be empty");

    let user_id = explicit_user_id.unwrap_or_else(Uuid::new_v4);
    workspace_service
        .create_personal_workspace_shell(user_id, name.trim())
        .await?;

    let register = Register {
        repo: user_repo,
        hasher,
    };
    let req = RegisterRequest {
        id: user_id,
        email: normalized_email.to_string(),
        name: name.trim().to_string(),
        password,
        default_workspace_id: user_id,
    };

    let user = match register.execute(&req).await {
        Ok(user) => user,
        Err(err) => {
            let _ = workspace_service.delete_workspace(user_id).await;
            return Err(err.context("failed to create user"));
        }
    };

    workspace_service
        .ensure_owner_membership(user_id, user_id)
        .await?;

    println!(
        "created user id={} email={} default_workspace={}",
        user.id, user.email, user_id
    );
    Ok(())
}

async fn delete_user(deps: &Deps, user_id: Uuid) -> Result<()> {
    let uc = DeleteAccount {
        user_repo: &deps.user_repo,
        document_repo: &deps.document_repo,
        plugin_installations: &deps.plugin_installations,
        plugin_repo: &deps.plugin_repo,
        plugin_assets: deps.plugin_assets.clone(),
        git_repo: &deps.git_repo,
        storage_jobs: deps.storage_jobs.as_ref(),
        files_repo: &deps.files_repo,
    };
    uc.execute(user_id).await?;
    let _ = deps.workspace_service.delete_workspace(user_id).await?;
    println!("deleted user {}", user_id);
    Ok(())
}

async fn set_password(
    pool: &PgPool,
    session_repo: &SqlxUserSessionRepository,
    hasher: &dyn SecretHasher,
    user_id: Uuid,
    password: String,
    revoke_sessions: bool,
) -> Result<()> {
    ensure!(!password.trim().is_empty(), "password must not be empty");

    let hash = hasher
        .hash_secret(&password)
        .map_err(|e| anyhow!(e.to_string()))?;

    let res = sqlx::query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await?;

    if res.rows_affected() == 0 {
        bail!("user not found");
    }

    if revoke_sessions {
        session_repo.revoke_all_for_user(user_id).await?;
        println!("password updated and sessions revoked for user {user_id}");
    } else {
        println!("password updated for user {user_id}");
    }

    Ok(())
}
