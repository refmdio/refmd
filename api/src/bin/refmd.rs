use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use password_hash::rand_core::OsRng;
use sqlx::{Row, types::Json};
use uuid::Uuid;

use api::application::ports::api_token_repository::ApiTokenRepository;
use api::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use api::application::ports::git_storage::GitStorage;
use api::application::ports::git_workspace::GitWorkspacePort;
use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::application::ports::shares_repository::SharesRepository;
use api::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use api::application::ports::storage_reconcile_jobs::StorageReconcileJobs;
use api::application::ports::user_session_repository::UserSessionRepository;
use api::application::services::api_tokens::generate_api_token;
use api::application::services::workspaces::WorkspaceService;
use api::application::use_cases::auth::delete_account::DeleteAccount;
use api::application::use_cases::auth::register::{Register, RegisterRequest};
use api::bootstrap::config::Config;
use api::domain::workspaces::permissions::PermissionSet;
use api::infrastructure::db;
use api::infrastructure::db::PgPool;
use api::infrastructure::db::repositories::api_token_repository_sqlx::SqlxApiTokenRepository;
use api::infrastructure::db::repositories::document_repository_sqlx::SqlxDocumentRepository;
use api::infrastructure::db::repositories::files_repository_sqlx::SqlxFilesRepository;
use api::infrastructure::db::repositories::plugin_installation_repository_sqlx::SqlxPluginInstallationRepository;
use api::infrastructure::db::repositories::plugin_repository_sqlx::SqlxPluginRepository;
use api::infrastructure::db::repositories::shares_repository_sqlx::SqlxSharesRepository;
use api::infrastructure::db::repositories::user_repository_sqlx::SqlxUserRepository;
use api::infrastructure::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository;
use api::infrastructure::db::repositories::workspace_repository_sqlx::SqlxWorkspaceRepository;
use api::infrastructure::git::PgGitRebuildJobQueue;
use api::infrastructure::git::storage::{GitStorageDriverConfig, build_git_storage};
use api::infrastructure::plugins::filesystem_store::{
    FilesystemPluginStore, PluginExecutionLimits,
};
use api::infrastructure::plugins::s3_store::{S3BackedPluginStore, S3PluginStoreConfig};
use api::infrastructure::storage::PgStorageIngestQueue;
use api::infrastructure::storage::PgStorageProjectionQueue;
use api::infrastructure::storage::PgStorageReconcileJobs;

#[derive(Parser)]
#[command(name = "refmd", about = "Admin CLI for managing a refmd node", version)]
struct Cli {
    /// Override the database URL (defaults to DATABASE_URL env / config)
    #[arg(long)]
    database_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
}

#[derive(Subcommand)]
enum UserCommand {
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
enum JobsCommand {
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
enum IngestCommand {
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
enum IngestKindArg {
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
enum ProjectionCommand {
    /// Print projection queue metrics
    Stats,
}

#[derive(Subcommand)]
enum ReconcileCommand {
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
enum GitRebuildCommand {
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
enum WorkspaceCommand {
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
enum TokenCommand {
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
enum ShareCommand {
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
enum GitCommand {
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
enum PluginCommand {
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

struct Deps {
    pool: PgPool,
    user_repo: SqlxUserRepository,
    workspace_service: Arc<WorkspaceService>,
    ingest_queue: PgStorageIngestQueue,
    reconcile_jobs: PgStorageReconcileJobs,
    git_rebuild_jobs: PgGitRebuildJobQueue,
    session_repo: SqlxUserSessionRepository,
    document_repo: SqlxDocumentRepository,
    files_repo: SqlxFilesRepository,
    plugin_installations: SqlxPluginInstallationRepository,
    plugin_repo: SqlxPluginRepository,
    api_tokens: SqlxApiTokenRepository,
    shares_repo: SqlxSharesRepository,
    plugin_assets: Arc<dyn PluginAssetStore>,
    git_repo: api::infrastructure::db::repositories::git_repository_sqlx::SqlxGitRepository,
    storage_jobs: PgStorageProjectionQueue,
    git_workspace: Arc<CliGitWorkspace>,
}

struct CliGitWorkspace {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
}

impl CliGitWorkspace {
    fn new(pool: PgPool, git_storage: Arc<dyn GitStorage>) -> Self {
        Self { pool, git_storage }
    }

    async fn load_repository_state(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<(bool, String)>> {
        let row = sqlx::query(
            "SELECT initialized, default_branch FROM git_repository_state WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("initialized"), r.get("default_branch"))))
    }

    async fn latest_commit_meta(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<api::application::ports::git_storage::CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1
               ORDER BY committed_at DESC
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| row_to_commit_meta(r)).transpose()
    }

    async fn fetch_dirty(&self, workspace_id: Uuid) -> anyhow::Result<Vec<DirtyRow>> {
        let rows = sqlx::query(
            r#"SELECT path, is_text, op, content_hash
               FROM git_dirty_files
               WHERE workspace_id = $1
               ORDER BY created_at ASC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let path: String = r.get("path");
            let op: String = r.get("op");
            let content_hash: Option<String> = r.try_get("content_hash").ok();
            out.push(DirtyRow {
                path,
                op,
                content_hash,
            });
        }
        Ok(out)
    }
}

struct DirtyRow {
    path: String,
    op: String,
    content_hash: Option<String>,
}

#[async_trait::async_trait]
impl GitWorkspacePort for CliGitWorkspace {
    async fn ensure_repository(
        &self,
        _workspace_id: Uuid,
        _default_branch: &str,
    ) -> anyhow::Result<()> {
        bail!("ensure_repository not supported in refmd CLI");
    }

    async fn remove_repository(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE git_repository_state SET initialized = false, updated_at = now() WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.git_storage.delete_all(workspace_id).await?;
        Ok(())
    }

    async fn status(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<api::application::dto::git::GitWorkspaceStatus> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((initialized, branch)) = state else {
            return Ok(api::application::dto::git::GitWorkspaceStatus {
                repository_initialized: false,
                current_branch: None,
                uncommitted_changes: 0,
                untracked_files: 0,
            });
        };
        if !initialized {
            return Ok(api::application::dto::git::GitWorkspaceStatus {
                repository_initialized: false,
                current_branch: Some(branch),
                uncommitted_changes: 0,
                untracked_files: 0,
            });
        }

        let latest = self.latest_commit_meta(workspace_id).await?;
        let previous_index: std::collections::HashMap<String, String> = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();

        let dirty = self.fetch_dirty(workspace_id).await?;
        let mut added: u32 = 0;
        let mut modified: u32 = 0;
        let mut deleted: u32 = 0;

        for d in dirty.iter() {
            match d.op.as_str() {
                "upsert" => {
                    if let Some(prev_hash) = previous_index.get(&d.path) {
                        match d.content_hash.as_ref() {
                            Some(h) if h == prev_hash => {}
                            _ => modified += 1,
                        }
                    } else {
                        added += 1;
                    }
                }
                "delete" => {
                    deleted += 1;
                }
                _ => {}
            }
        }

        Ok(api::application::dto::git::GitWorkspaceStatus {
            repository_initialized: true,
            current_branch: Some(branch),
            uncommitted_changes: modified + deleted,
            untracked_files: added,
        })
    }

    async fn list_changes(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<api::application::dto::git::GitChangeItem>> {
        if let Some((initialized, _)) = self.load_repository_state(workspace_id).await? {
            if !initialized {
                return Ok(Vec::new());
            }
        } else {
            return Ok(Vec::new());
        }

        let latest = self.latest_commit_meta(workspace_id).await?;
        let previous_index: std::collections::HashMap<String, String> = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let dirty = self.fetch_dirty(workspace_id).await?;

        let mut out = Vec::new();
        for d in dirty {
            let status = match d.op.as_str() {
                "delete" => "deleted",
                "upsert" => {
                    if previous_index.contains_key(&d.path) {
                        "modified"
                    } else {
                        "added"
                    }
                }
                _ => "unknown",
            };
            out.push(api::application::dto::git::GitChangeItem {
                path: d.path,
                status: status.to_string(),
            });
        }
        Ok(out)
    }

    async fn working_diff(
        &self,
        _workspace_id: Uuid,
    ) -> anyhow::Result<Vec<api::application::dto::diff::TextDiffResult>> {
        bail!("working_diff not supported in refmd CLI");
    }

    async fn commit_diff(
        &self,
        _workspace_id: Uuid,
        _from: &str,
        _to: &str,
    ) -> anyhow::Result<Vec<api::application::dto::diff::TextDiffResult>> {
        bail!("commit_diff not supported in refmd CLI");
    }

    async fn history(
        &self,
        _workspace_id: Uuid,
    ) -> anyhow::Result<Vec<api::application::dto::git::GitCommitInfo>> {
        bail!("history not supported in refmd CLI");
    }

    async fn sync(
        &self,
        _workspace_id: Uuid,
        _req: &api::application::dto::git::GitSyncRequestDto,
        _cfg: Option<&api::application::ports::git_repository::UserGitCfg>,
    ) -> anyhow::Result<api::application::dto::git::GitSyncOutcome> {
        bail!("sync not supported in refmd CLI");
    }

    async fn pull(
        &self,
        _workspace_id: Uuid,
        _req: &api::application::dto::git::GitPullRequestDto,
        _cfg: &api::application::ports::git_repository::UserGitCfg,
    ) -> anyhow::Result<api::application::dto::git::GitPullResultDto> {
        bail!("pull not supported in refmd CLI");
    }

    async fn head_commit(&self, workspace_id: Uuid) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .latest_commit_meta(workspace_id)
            .await?
            .map(|m| m.commit_id))
    }

    async fn remote_head(
        &self,
        _workspace_id: Uuid,
        _cfg: &api::application::ports::git_repository::UserGitCfg,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn has_pending_changes(&self, workspace_id: Uuid) -> anyhow::Result<bool> {
        let dirty_rows = self.fetch_dirty(workspace_id).await?;
        Ok(!dirty_rows.is_empty())
    }

    async fn drift_since_commit(
        &self,
        workspace_id: Uuid,
        base_commit: &[u8],
    ) -> anyhow::Result<bool> {
        // CLI helper: fallback to dirty check when full state comparison is not available.
        if self.has_pending_changes(workspace_id).await? {
            return Ok(true);
        }
        // If the base commit is not the latest, consider it stale.
        let latest = self.latest_commit_meta(workspace_id).await?;
        if let Some(meta) = latest {
            if meta.commit_id.as_slice() != base_commit {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn build_synthetic_commit(
        &self,
        _workspace_id: Uuid,
        _repo: &git2::Repository,
        _remote_oid: git2::Oid,
    ) -> anyhow::Result<git2::Oid> {
        anyhow::bail!("not supported in CLI")
    }

    async fn check_remote(
        &self,
        _workspace_id: Uuid,
        _cfg: &api::application::ports::git_repository::UserGitCfg,
    ) -> anyhow::Result<api::application::dto::git::GitRemoteCheckDto> {
        Ok(api::application::dto::git::GitRemoteCheckDto {
            ok: false,
            message: "remote check not supported in CLI".to_string(),
            reason: Some("unsupported".to_string()),
        })
    }
}

fn row_to_commit_meta(
    row: sqlx::postgres::PgRow,
) -> anyhow::Result<api::application::ports::git_storage::CommitMeta> {
    let commit_id: Vec<u8> = row.get("commit_id");
    let parent_commit_id: Option<Vec<u8>> = row.try_get("parent_commit_id").ok();
    let message: Option<String> = row.try_get("message").ok();
    let author_name: Option<String> = row.try_get("author_name").ok();
    let author_email: Option<String> = row.try_get("author_email").ok();
    let committed_at: DateTime<Utc> = row.get("committed_at");
    let pack_key: String = row.get("pack_key");
    let file_hash_index: Json<std::collections::HashMap<String, String>> =
        row.get("file_hash_index");

    Ok(api::application::ports::git_storage::CommitMeta {
        commit_id,
        parent_commit_id,
        message,
        author_name,
        author_email,
        committed_at,
        pack_key,
        file_hash_index: file_hash_index.0,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let cfg = Config::from_env()?;
    let database_url = cli.database_url.unwrap_or(cfg.database_url.clone());

    let pool = db::connect_pool(&database_url)
        .await
        .context("failed to connect to database")?;

    let user_repo = SqlxUserRepository::new(pool.clone());
    let workspace_repo = SqlxWorkspaceRepository::new(pool.clone());
    let workspace_service = Arc::new(WorkspaceService::new(Arc::new(workspace_repo)));
    let ingest_queue = PgStorageIngestQueue::new(pool.clone());
    let storage_jobs = PgStorageProjectionQueue::new(pool.clone());
    let reconcile_jobs = PgStorageReconcileJobs::new(pool.clone());
    let git_rebuild_jobs = PgGitRebuildJobQueue::new(pool.clone());
    let session_repo = SqlxUserSessionRepository::new(pool.clone());
    let document_repo = SqlxDocumentRepository::new(pool.clone());
    let files_repo = SqlxFilesRepository::new(pool.clone());
    let plugin_installations = SqlxPluginInstallationRepository::new(pool.clone());
    let plugin_repo = SqlxPluginRepository::new(pool.clone());
    let api_tokens = SqlxApiTokenRepository::new(pool.clone());
    let shares_repo = SqlxSharesRepository::new(pool.clone());
    let plugin_limits = {
        let timeout = if cfg.plugin_timeout_secs == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(cfg.plugin_timeout_secs))
        };
        let memory_pages_raw = cfg.plugin_memory_max_mb.saturating_mul(16);
        let memory_max_pages = if memory_pages_raw == 0 {
            None
        } else {
            Some(memory_pages_raw.min(u32::MAX as u64) as u32)
        };
        let fuel_limit = cfg
            .plugin_fuel_limit
            .and_then(|limit| if limit == 0 { None } else { Some(limit) });
        PluginExecutionLimits::new(timeout, memory_max_pages, fuel_limit)
    };
    let plugin_assets: Arc<dyn PluginAssetStore> = match cfg.storage_backend {
        api::bootstrap::config::StorageBackend::Filesystem => {
            Arc::new(FilesystemPluginStore::new(&cfg.plugin_dir, plugin_limits)?)
        }
        api::bootstrap::config::StorageBackend::S3 => {
            let s3_cfg = S3PluginStoreConfig {
                plugin_dir: cfg.plugin_dir.clone(),
                bucket: cfg
                    .s3_bucket
                    .clone()
                    .context("S3_BUCKET must be configured when using S3 storage backend")?,
                region: cfg.s3_region.clone(),
                endpoint: cfg.s3_endpoint.clone(),
                access_key: cfg.s3_access_key.clone(),
                secret_key: cfg.s3_secret_key.clone(),
                use_path_style: cfg.s3_use_path_style,
            };
            Arc::new(S3BackedPluginStore::new(&s3_cfg, plugin_limits).await?)
        }
    };
    let git_repo =
        api::infrastructure::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        );
    let git_storage_cfg = match cfg.storage_backend {
        api::bootstrap::config::StorageBackend::Filesystem => GitStorageDriverConfig::Filesystem {
            root: PathBuf::from(cfg.storage_root.clone()),
        },
        api::bootstrap::config::StorageBackend::S3 => {
            let s3_settings = api::infrastructure::git::storage::S3GitStorageConfig {
                storage_root_prefix: cfg.storage_root.clone(),
                bucket: cfg
                    .s3_bucket
                    .clone()
                    .context("S3_BUCKET must be configured when using S3 storage backend")?,
                region: cfg.s3_region.clone(),
                endpoint: cfg.s3_endpoint.clone(),
                access_key: cfg.s3_access_key.clone(),
                secret_key: cfg.s3_secret_key.clone(),
                use_path_style: cfg.s3_use_path_style,
            };
            GitStorageDriverConfig::S3(s3_settings)
        }
    };
    let git_storage = build_git_storage(git_storage_cfg).await?;
    let git_workspace = Arc::new(CliGitWorkspace::new(pool.clone(), git_storage.clone()));

    let deps = Deps {
        pool,
        user_repo,
        workspace_service,
        ingest_queue,
        storage_jobs,
        reconcile_jobs,
        git_rebuild_jobs,
        session_repo,
        document_repo,
        files_repo,
        plugin_installations,
        plugin_repo,
        api_tokens,
        shares_repo,
        plugin_assets,
        git_repo,
        git_workspace,
    };

    match cli.command {
        Command::Users { command } => handle_users(&deps, command).await?,
        Command::Jobs { command } => handle_jobs(&deps, command).await?,
        Command::Workspaces { command } => handle_workspaces(&deps, command).await?,
        Command::Git { command } => handle_git(&deps, command).await?,
        Command::Plugins { command } => handle_plugins(&deps, command).await?,
        Command::Tokens { command } => handle_tokens(&deps, command).await?,
        Command::Shares { command } => handle_shares(&deps, command).await?,
    }

    Ok(())
}

async fn handle_users(deps: &Deps, cmd: UserCommand) -> Result<()> {
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

async fn handle_jobs(deps: &Deps, cmd: JobsCommand) -> Result<()> {
    match cmd {
        JobsCommand::Ingest { command } => match command {
            IngestCommand::Stats => print_ingest_stats(&deps.ingest_queue).await,
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
                    &deps.ingest_queue,
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

async fn handle_workspaces(deps: &Deps, cmd: WorkspaceCommand) -> Result<()> {
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

async fn handle_tokens(deps: &Deps, cmd: TokenCommand) -> Result<()> {
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

async fn handle_shares(deps: &Deps, cmd: ShareCommand) -> Result<()> {
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

async fn handle_git(deps: &Deps, cmd: GitCommand) -> Result<()> {
    match cmd {
        GitCommand::Status { workspace_id } => {
            let status = deps.git_workspace.status(workspace_id).await?;
            println!(
                "initialized={} branch={:?} uncommitted_changes={} untracked_files={}",
                status.repository_initialized,
                status.current_branch,
                status.uncommitted_changes,
                status.untracked_files
            );
            Ok(())
        }
        GitCommand::Changes { workspace_id } => {
            let changes = deps.git_workspace.list_changes(workspace_id).await?;
            println!("{} change(s)", changes.len());
            for c in changes {
                println!("{} {}", c.status, c.path);
            }
            Ok(())
        }
        GitCommand::Remove { workspace_id } => {
            deps.git_workspace.remove_repository(workspace_id).await?;
            println!("removed git workspace {}", workspace_id);
            Ok(())
        }
    }
}

async fn handle_plugins(deps: &Deps, cmd: PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::ListGlobal => {
            let manifests = deps.plugin_assets.list_latest_global_manifests().await?;
            println!("{} global plugin(s)", manifests.len());
            for (plugin_id, version, manifest) in manifests {
                println!(
                    "{}@{} manifest={}",
                    plugin_id,
                    version,
                    serde_json::to_string(&manifest)?
                );
            }
            Ok(())
        }
        PluginCommand::UserManifest {
            user_id,
            plugin_id,
            version,
        } => {
            match deps
                .plugin_assets
                .load_user_manifest(&user_id, &plugin_id, &version)
                .await?
            {
                Some(manifest) => {
                    println!(
                        "manifest for {} user {}:\n{}",
                        plugin_id,
                        user_id,
                        serde_json::to_string_pretty(&manifest)?
                    );
                }
                None => println!(
                    "manifest not found for plugin={} user={} version={}",
                    plugin_id, user_id, version
                ),
            }
            Ok(())
        }
        PluginCommand::RemoveUserDir { user_id, plugin_id } => {
            deps.plugin_assets
                .remove_user_plugin_dir(&user_id, &plugin_id)
                .await?;
            println!(
                "removed plugin data for user {} plugin {}",
                user_id, plugin_id
            );
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
    workspace_service: &WorkspaceService,
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

    let register = Register { repo: user_repo };
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
        git_workspace: deps.git_workspace.as_ref(),
        storage_jobs: &deps.storage_jobs,
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
    user_id: Uuid,
    password: String,
    revoke_sessions: bool,
) -> Result<()> {
    ensure!(!password.trim().is_empty(), "password must not be empty");

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!(e.to_string()))?
        .to_string();

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

async fn print_ingest_stats(queue: &PgStorageIngestQueue) -> Result<()> {
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

async fn enqueue_ingest(
    queue: &PgStorageIngestQueue,
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
            backend.trim(),
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
