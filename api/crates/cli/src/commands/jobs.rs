use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use domain::storage::ingest_backend::StorageIngestBackend;
use domain::workspaces::permissions::PermissionSet;
use infrastructure::core::db::PgPool;

use application::core::ports::storage::storage_ingest_queue::StorageIngestQueue;

use crate::cli::{
    GitRebuildCommand, IngestCommand, IngestKindArg, JobsCommand, ProjectionCommand,
    ReconcileCommand,
};
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: JobsCommand) -> Result<()> {
    match cmd {
        JobsCommand::Ingest { command } => match command {
            IngestCommand::Stats => print_ingest_stats(deps.ingest_queue.as_ref()).await,
            IngestCommand::Enqueue {
                workspace_id,
                user_id,
                repo_path,
                backend,
                kind,
                content_hash,
                actor_id,
            } => {
                enqueue_ingest(
                    deps.ingest_queue.as_ref(),
                    workspace_id,
                    user_id,
                    actor_id,
                    repo_path,
                    backend,
                    kind,
                    content_hash,
                )
                .await
            }
        },
        JobsCommand::Projection { command } => match command {
            ProjectionCommand::Stats => print_projection_stats(&deps.pool).await,
        },
        JobsCommand::Reconcile { command } => match command {
            ReconcileCommand::Stats => print_reconcile_stats(&deps.pool).await,
            ReconcileCommand::Enqueue {
                workspace_id,
                scope,
            } => {
                deps.reconcile_jobs
                    .enqueue(workspace_id, scope.trim())
                    .await?;
                println!(
                    "enqueued reconcile job workspace={workspace_id} scope={}",
                    scope.trim()
                );
                Ok(())
            }
        },
        JobsCommand::GitRebuild { command } => match command {
            GitRebuildCommand::Stats => print_git_rebuild_stats(&deps.pool).await,
            GitRebuildCommand::Enqueue {
                workspace_id,
                actor_id,
            } => {
                let permissions = PermissionSet::all().to_vec();
                deps.git_rebuild_jobs
                    .enqueue(workspace_id, actor_id, &permissions)
                    .await?;
                println!(
                    "enqueued git rebuild workspace={} actor_id={:?}",
                    workspace_id, actor_id
                );
                Ok(())
            }
        },
    }
}

async fn print_ingest_stats(queue: &dyn StorageIngestQueue) -> Result<()> {
    let stats = queue.stats().await?;
    println!("storage_ingest.pending={}", stats.pending);
    println!("storage_ingest.locked={}", stats.locked);
    println!("storage_ingest.distinct_users={}", stats.distinct_users);
    match stats.oldest_created_at {
        Some(ts) => println!(
            "storage_ingest.oldest_pending_age_secs={}",
            (Utc::now() - ts).num_seconds()
        ),
        None => println!("storage_ingest.oldest_pending_age_secs=-"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_ingest(
    queue: &dyn StorageIngestQueue,
    workspace_id: Uuid,
    user_id: Uuid,
    actor_id: Option<Uuid>,
    repo_path: String,
    backend: String,
    kind: IngestKindArg,
    content_hash: Option<String>,
) -> Result<()> {
    let permissions = PermissionSet::all().to_vec();
    queue
        .enqueue_event(
            workspace_id,
            user_id,
            actor_id.or(Some(user_id)),
            repo_path.trim(),
            StorageIngestBackend::parse(backend.trim()),
            kind.into(),
            content_hash.as_deref(),
            None,
            &permissions,
        )
        .await?;

    println!(
        "enqueued ingest workspace={} user={} repo_path={} backend={} kind={:?}",
        workspace_id,
        user_id,
        repo_path.trim(),
        backend.trim(),
        kind
    );
    Ok(())
}

async fn print_projection_stats(pool: &PgPool) -> Result<()> {
    let row = sqlx::query(
        r#"SELECT
                COUNT(*) FILTER (WHERE locked_at IS NULL) AS pending,
                COUNT(*) FILTER (WHERE locked_at IS NOT NULL) AS locked,
                COUNT(*) FILTER (WHERE pending_retry) AS retrying,
                COUNT(*) AS total,
                MIN(created_at) FILTER (WHERE locked_at IS NULL) AS oldest_created_at
            FROM storage_projection_jobs"#,
    )
    .fetch_one(pool)
    .await?;

    let pending: i64 = row.try_get("pending").unwrap_or(0);
    let locked: i64 = row.try_get("locked").unwrap_or(0);
    let retrying: i64 = row.try_get("retrying").unwrap_or(0);
    let total: i64 = row.try_get("total").unwrap_or(0);
    let oldest_created_at: Option<DateTime<Utc>> = row.try_get("oldest_created_at").ok();

    println!("storage_projection.total={total}");
    println!("storage_projection.pending={pending}");
    println!("storage_projection.locked={locked}");
    println!("storage_projection.retrying={retrying}");
    match oldest_created_at {
        Some(ts) => println!(
            "storage_projection.oldest_pending_age_secs={}",
            (Utc::now() - ts).num_seconds()
        ),
        None => println!("storage_projection.oldest_pending_age_secs=-"),
    }
    Ok(())
}

async fn print_reconcile_stats(pool: &PgPool) -> Result<()> {
    let row = sqlx::query(
        r#"SELECT
                COUNT(*) FILTER (WHERE locked_at IS NULL) AS pending,
                COUNT(*) FILTER (WHERE locked_at IS NOT NULL) AS locked,
                COUNT(*) FILTER (WHERE pending_retry) AS retrying,
                COUNT(*) AS total,
                MIN(created_at) FILTER (WHERE locked_at IS NULL) AS oldest_created_at
            FROM storage_reconcile_jobs"#,
    )
    .fetch_one(pool)
    .await?;

    let pending: i64 = row.try_get("pending").unwrap_or(0);
    let locked: i64 = row.try_get("locked").unwrap_or(0);
    let retrying: i64 = row.try_get("retrying").unwrap_or(0);
    let total: i64 = row.try_get("total").unwrap_or(0);
    let oldest_created_at: Option<DateTime<Utc>> = row.try_get("oldest_created_at").ok();

    println!("storage_reconcile.total={total}");
    println!("storage_reconcile.pending={pending}");
    println!("storage_reconcile.locked={locked}");
    println!("storage_reconcile.retrying={retrying}");
    match oldest_created_at {
        Some(ts) => println!(
            "storage_reconcile.oldest_pending_age_secs={}",
            (Utc::now() - ts).num_seconds()
        ),
        None => println!("storage_reconcile.oldest_pending_age_secs=-"),
    }
    Ok(())
}

async fn print_git_rebuild_stats(pool: &PgPool) -> Result<()> {
    let row = sqlx::query(
        r#"SELECT
                COUNT(*) FILTER (WHERE locked_at IS NULL) AS pending,
                COUNT(*) FILTER (WHERE locked_at IS NOT NULL) AS locked,
                COUNT(*) FILTER (WHERE pending_retry) AS retrying,
                COUNT(*) AS total,
                MIN(updated_at) FILTER (WHERE locked_at IS NOT NULL) AS oldest_locked_at,
                MIN(created_at) FILTER (WHERE locked_at IS NULL) AS oldest_pending_created
            FROM git_rebuild_jobs"#,
    )
    .fetch_one(pool)
    .await?;

    let pending: i64 = row.try_get("pending").unwrap_or(0);
    let locked: i64 = row.try_get("locked").unwrap_or(0);
    let retrying: i64 = row.try_get("retrying").unwrap_or(0);
    let total: i64 = row.try_get("total").unwrap_or(0);
    let oldest_locked_at: Option<DateTime<Utc>> = row.try_get("oldest_locked_at").ok();
    let oldest_pending: Option<DateTime<Utc>> = row.try_get("oldest_pending_created").ok();

    println!("git_rebuild.total={total}");
    println!("git_rebuild.pending={pending}");
    println!("git_rebuild.locked={locked}");
    println!("git_rebuild.retrying={retrying}");
    match oldest_pending {
        Some(ts) => println!(
            "git_rebuild.oldest_pending_age_secs={}",
            (Utc::now() - ts).num_seconds()
        ),
        None => println!("git_rebuild.oldest_pending_age_secs=-"),
    }
    match oldest_locked_at {
        Some(ts) => println!(
            "git_rebuild.oldest_locked_age_secs={}",
            (Utc::now() - ts).num_seconds()
        ),
        None => println!("git_rebuild.oldest_locked_age_secs=-"),
    }
    Ok(())
}
