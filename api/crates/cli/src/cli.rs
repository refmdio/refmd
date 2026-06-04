use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use bootstrap::application::core::ports::storage::storage_ingest_queue::StorageIngestKind;

#[derive(Parser)]
#[command(name = "refmd", about = "Admin CLI for managing a refmd node", version)]
pub(crate) struct Cli {
    /// Override the database URL (defaults to DATABASE_URL env / config)
    #[arg(long)]
    pub(crate) database_url: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// User lifecycle and session management
    Users {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Queue-level maintenance and enqueue helpers
    Jobs {
        #[command(subcommand)]
        command: JobsCommand,
    },
    /// Workspace lifecycle and membership helpers
    Workspaces {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    /// Git workspace helpers
    Git {
        #[command(subcommand)]
        command: GitCommand,
    },
    /// Plugin asset utilities
    Plugins {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// API token management
    Tokens {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Share management
    Shares {
        #[command(subcommand)]
        command: ShareCommand,
    },
    /// Snapshot maintenance
    Snapshots {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    /// OpenAPI utilities
    Openapi {
        #[command(subcommand)]
        command: OpenapiCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum OpenapiCommand {
    /// Print OpenAPI JSON to stdout
    Export,
}

#[derive(Subcommand)]
pub(crate) enum UserCommand {
    /// List all users with their default workspace IDs
    List,
    /// Create a new user and provision their personal workspace
    Create {
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        password: String,
        /// Optional explicit user ID (defaults to a new UUID v4)
        #[arg(long)]
        user_id: Option<Uuid>,
    },
    /// Update a user's password hash (optionally revoking active sessions)
    SetPassword {
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = false)]
        revoke_sessions: bool,
    },
    /// Delete a user (runs full account deletion path)
    Delete {
        #[arg(long)]
        user_id: Uuid,
    },
    /// List sessions for a user
    Sessions {
        #[arg(long)]
        user_id: Uuid,
    },
    /// Revoke all active sessions for a user
    RevokeSessions {
        #[arg(long)]
        user_id: Uuid,
    },
}

#[derive(Subcommand)]
pub(crate) enum JobsCommand {
    /// Storage ingest queue operations
    Ingest {
        #[command(subcommand)]
        command: IngestCommand,
    },
    /// Storage projection job operations
    Projection {
        #[command(subcommand)]
        command: ProjectionCommand,
    },
    /// Storage reconcile job operations
    Reconcile {
        #[command(subcommand)]
        command: ReconcileCommand,
    },
    /// Git rebuild job operations
    GitRebuild {
        #[command(subcommand)]
        command: GitRebuildCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum IngestCommand {
    /// Print queue depth and age metrics
    Stats,
    /// Enqueue an ingest event for a workspace path
    Enqueue {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        repo_path: String,
        #[arg(long, default_value = "fs")]
        backend: String,
        #[arg(long, value_enum)]
        kind: IngestKindArg,
        #[arg(long)]
        content_hash: Option<String>,
        /// Optional actor ID to attribute enqueueing
        #[arg(long)]
        actor_id: Option<Uuid>,
    },
}

#[derive(Clone, Copy, ValueEnum, Debug)]
pub(crate) enum IngestKindArg {
    Upsert,
    Delete,
}

impl From<IngestKindArg> for StorageIngestKind {
    fn from(value: IngestKindArg) -> StorageIngestKind {
        match value {
            IngestKindArg::Upsert => StorageIngestKind::Upsert,
            IngestKindArg::Delete => StorageIngestKind::Delete,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum ProjectionCommand {
    /// Print projection queue metrics
    Stats,
}

#[derive(Subcommand)]
pub(crate) enum ReconcileCommand {
    /// Print reconcile queue metrics
    Stats,
    /// Enqueue a reconcile job for a workspace and scope (e.g. "full")
    Enqueue {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        scope: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum GitRebuildCommand {
    /// Print git rebuild queue metrics
    Stats,
    /// Enqueue a git rebuild job for a workspace
    Enqueue {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        actor_id: Option<Uuid>,
    },
}

#[derive(Subcommand)]
pub(crate) enum SnapshotCommand {
    /// Print snapshot retention metrics
    Stats {
        /// Keep this many latest document_snapshots per document
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        snapshots_keep: Option<i64>,
        /// Keep this many latest document_snapshot_archives per document/kind
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        archives_keep: Option<i64>,
        /// Archive kind to include in archive stats
        #[arg(long, value_enum, default_value_t = SnapshotArchiveKindArg::Auto)]
        archive_kind: SnapshotArchiveKindArg,
        /// Which table family to inspect
        #[arg(long, value_enum, default_value_t = SnapshotPruneTarget::Both)]
        target: SnapshotPruneTarget,
    },
    /// Apply snapshot retention to existing rows
    Prune {
        /// Keep this many latest document_snapshots per document
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        snapshots_keep: Option<i64>,
        /// Keep this many latest document_snapshot_archives per document/kind
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        archives_keep: Option<i64>,
        /// Archive kind to prune
        #[arg(long, value_enum, default_value_t = SnapshotArchiveKindArg::Auto)]
        archive_kind: SnapshotArchiveKindArg,
        /// Which table family to prune
        #[arg(long, value_enum, default_value_t = SnapshotPruneTarget::Both)]
        target: SnapshotPruneTarget,
        /// Maximum over-limit documents to select in each pass
        #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(i64).range(1..))]
        document_batch_size: i64,
        /// Maximum rows to delete in each statement
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(i64).range(1..))]
        delete_batch_size: i64,
        /// Stop after this many documents per target, useful for canary runs
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        max_docs: Option<i64>,
        /// Sleep between delete statements
        #[arg(long, default_value_t = 0)]
        sleep_ms: u64,
        /// Print what would be deleted without deleting rows
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotPruneTarget {
    Snapshots,
    Archives,
    Both,
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotArchiveKindArg {
    Auto,
    Manual,
    Restore,
}

impl SnapshotArchiveKindArg {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SnapshotArchiveKindArg::Auto => "auto",
            SnapshotArchiveKindArg::Manual => "manual",
            SnapshotArchiveKindArg::Restore => "restore",
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum WorkspaceCommand {
    /// List all workspaces
    List,
    /// Show members for a workspace
    Members {
        #[arg(long)]
        workspace_id: Uuid,
    },
    /// Delete a workspace (cascades documents/files/shares)
    Delete {
        #[arg(long)]
        workspace_id: Uuid,
    },
}

#[derive(Subcommand)]
pub(crate) enum TokenCommand {
    /// List API tokens for a workspace
    List {
        #[arg(long)]
        workspace_id: Uuid,
    },
    /// Create a new API token (prints plaintext once)
    Create {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        owner_id: Uuid,
        #[arg(long)]
        name: Option<String>,
    },
    /// Revoke an API token
    Revoke {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        token_id: Uuid,
    },
}

#[derive(Subcommand)]
pub(crate) enum ShareCommand {
    /// List shares for a document
    List {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        document_id: Uuid,
    },
    /// Revoke a share token
    Revoke {
        #[arg(long)]
        workspace_id: Uuid,
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum GitCommand {
    /// Show git workspace status summary
    Status {
        #[arg(long)]
        workspace_id: Uuid,
    },
    /// List dirty changes tracked for a workspace
    Changes {
        #[arg(long)]
        workspace_id: Uuid,
    },
    /// Remove git workspace data (DB + storage)
    Remove {
        #[arg(long)]
        workspace_id: Uuid,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginCommand {
    /// List latest global plugin manifests
    ListGlobal,
    /// Load a user-scoped plugin manifest
    UserManifest {
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        plugin_id: String,
        #[arg(long)]
        version: String,
    },
    /// Remove a user's plugin directory for a plugin
    RemoveUserDir {
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        plugin_id: String,
    },
}
