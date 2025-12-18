use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use application::core::ports::storage::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use bootstrap::config::Config;
use domain::storage::ingest_backend::StorageIngestBackend;
use domain::workspaces::permissions::PermissionSet;
use infrastructure::core::db;
use infrastructure::core::storage::PgStorageIngestQueue;

#[derive(Parser)]
#[command(about = "Inspect and enqueue storage ingest events", version)]
struct Cli {
    /// Override the database URL (defaults to DATABASE_URL env / config)
    #[arg(long)]
    database_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print queue depth and age metrics
    Stats,
    /// Enqueue a new ingest event (for CI/Bot flows)
    Enqueue {
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        repo_path: String,
        #[arg(long, default_value = "fs")]
        backend: String,
        #[arg(long, value_enum)]
        kind: KindArg,
        #[arg(long)]
        content_hash: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum KindArg {
    Upsert,
    Delete,
}

impl From<KindArg> for StorageIngestKind {
    fn from(value: KindArg) -> StorageIngestKind {
        match value {
            KindArg::Upsert => StorageIngestKind::Upsert,
            KindArg::Delete => StorageIngestKind::Delete,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let database_url = match cli.database_url {
        Some(url) => url,
        None => Config::from_env()?.database_url,
    };

    let pool = db::connect_pool(&database_url)
        .await
        .context("failed to connect to database")?;
    let queue = PgStorageIngestQueue::new(pool);

    match cli.command {
        Command::Stats => {
            let stats = queue.stats().await?;
            println!("pending: {}", stats.pending);
            println!("locked: {}", stats.locked);
            println!("distinct_users: {}", stats.distinct_users);
            if let Some(oldest) = stats.oldest_created_at {
                println!(
                    "oldest_pending_age_secs: {}",
                    (chrono::Utc::now() - oldest).num_seconds()
                );
            } else {
                println!("oldest_pending_age_secs: -");
            }
        }
        Command::Enqueue {
            user_id,
            repo_path,
            backend,
            kind,
            content_hash,
        } => {
            let permissions = PermissionSet::all().to_vec();
            queue
                .enqueue_event(
                    user_id,
                    user_id,
                    None,
                    repo_path.trim(),
                    StorageIngestBackend::parse(backend.trim()),
                    kind.into(),
                    content_hash.as_deref(),
                    None,
                    &permissions,
                )
                .await?;
            println!(
                "enqueued ingest event user={} path={} backend={} kind={:?}",
                user_id, repo_path, backend, kind
            );
        }
    }
    Ok(())
}
