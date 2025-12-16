use axum::extract::{DefaultBodyLimit, MatchedPath};
use axum::{Router, middleware, routing::get};
use http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;
use presentation::context::AppContext;

#[derive(OpenApi)]
#[openapi(
        paths(
            presentation::http::auth::register,
            presentation::http::auth::login,
            presentation::http::auth::oauth_state,
            presentation::http::auth::oauth_login,
            presentation::http::auth::list_oauth_providers,
            presentation::http::auth::refresh_session,
            presentation::http::auth::logout,
            presentation::http::auth::me,
            presentation::http::auth::list_sessions,
            presentation::http::auth::revoke_session,
            presentation::http::api_tokens::list_api_tokens,
            presentation::http::api_tokens::create_api_token,
            presentation::http::api_tokens::revoke_api_token,
            presentation::http::shortcuts::get_user_shortcuts,
            presentation::http::shortcuts::update_user_shortcuts,
            presentation::http::tags::list_tags,
            presentation::ws::axum_ws_entry,
            presentation::http::documents::list_documents,
            presentation::http::documents::create_document,
            presentation::http::documents::get_document,
            presentation::http::documents::update_document,
            presentation::http::documents::duplicate_document,
            presentation::http::documents::delete_document,
            presentation::http::documents::get_document_content,
            presentation::http::documents::download_document,
            presentation::http::documents::list_document_snapshots,
            presentation::http::documents::get_document_snapshot_diff,
            presentation::http::documents::restore_document_snapshot,
            presentation::http::documents::download_document_snapshot,
            presentation::http::documents::search_documents,
            presentation::http::documents::get_backlinks,
            presentation::http::documents::get_outgoing_links,
            presentation::http::files::upload_file,
            presentation::http::files::get_file,
            presentation::http::files::get_file_by_name,
            presentation::http::shares::create_share,
            presentation::http::shares::delete_share,
            presentation::http::shares::list_document_shares,
            presentation::http::shares::validate_share_token,
            presentation::http::shares::browse_share,
            presentation::http::shares::list_active_shares,
            presentation::http::shares::create_share_mount,
            presentation::http::shares::list_share_mounts,
            presentation::http::shares::delete_share_mount,
            presentation::http::shares::list_applicable_shares,
            presentation::http::shares::materialize_folder_share,
            presentation::http::public::publish_document,
            presentation::http::public::unpublish_document,
            presentation::http::public::get_publish_status,
            presentation::http::public::list_workspace_public_documents,
            presentation::http::public::get_public_by_workspace_and_id,
            presentation::http::public::get_public_content_by_workspace_and_id,
            presentation::http::git::get_config,
            presentation::http::git::create_or_update_config,
            presentation::http::git::delete_config,
            presentation::http::git::get_status,
            presentation::http::git::get_changes,
            presentation::http::git::get_history,
            presentation::http::git::get_working_diff,
            presentation::http::git::get_commit_diff,
            presentation::http::git::sync_now,
            presentation::http::git::import_repository,
            presentation::http::git::start_pull_session,
            presentation::http::git::get_pull_session,
            presentation::http::git::resolve_pull_session,
            presentation::http::git::finalize_pull_session,
            presentation::http::git::init_repository,
            presentation::http::git::deinit_repository,
            presentation::http::git::ignore_document,
            presentation::http::git::ignore_folder,
            presentation::http::git::get_gitignore_patterns,
            presentation::http::git::add_gitignore_patterns,
            presentation::http::git::check_path_ignored,
            presentation::http::storage_ingest::enqueue_ingest_events,
            presentation::http::markdown::render_markdown,
            presentation::http::markdown::render_markdown_many,
            presentation::http::workspaces::list_workspaces,
            presentation::http::workspaces::create_workspace,
            presentation::http::workspaces::switch_workspace,
            presentation::http::workspaces::list_members,
            presentation::http::workspaces::update_member_role,
            presentation::http::workspaces::get_workspace_permissions,
            presentation::http::workspaces::list_roles,
            presentation::http::workspaces::create_role,
            presentation::http::workspaces::update_role,
            presentation::http::workspaces::delete_role,
            presentation::http::workspaces::list_invitations,
            presentation::http::workspaces::create_invitation,
            presentation::http::workspaces::accept_invitation,
            presentation::http::workspaces::download_workspace_archive,
            presentation::http::plugins::get_manifest,
            presentation::http::plugins::exec_action,
            presentation::http::plugins::list_records,
            presentation::http::plugins::create_record,
            presentation::http::plugins::update_record,
            presentation::http::plugins::delete_record,
            presentation::http::plugins::get_kv_value,
            presentation::http::plugins::put_kv_value,
            presentation::http::plugins::install_from_url,
            presentation::http::plugins::uninstall,
            presentation::http::plugins::sse_updates,
            presentation::http::health::health,
        ),
        components(schemas(
            presentation::http::auth::RegisterRequest,
            presentation::http::auth::LoginRequest,
            presentation::http::auth::LoginResponse,
            presentation::http::auth::OAuthLoginRequest,
            presentation::http::auth::OAuthStateResponse,
            presentation::http::auth::UserResponse,
            presentation::http::auth::WorkspaceMembershipResponse,
            presentation::http::api_tokens::ApiTokenItem,
            presentation::http::api_tokens::ApiTokenCreateRequest,
            presentation::http::api_tokens::ApiTokenCreateResponse,
            presentation::http::tags::TagItem,
            presentation::http::documents::Document,
            presentation::http::documents::DocumentListResponse,
            presentation::http::documents::CreateDocumentRequest,
            presentation::http::documents::UpdateDocumentRequest,
            presentation::http::documents::DuplicateDocumentRequest,
            presentation::http::documents::BacklinkInfo,
            presentation::http::documents::BacklinksResponse,
            presentation::http::documents::OutgoingLink,
            presentation::http::documents::OutgoingLinksResponse,
            presentation::http::documents::SearchResult,
            presentation::http::files::UploadFileResponse,
            presentation::http::files::UploadFileMultipart,
            presentation::http::shares::CreateShareRequest,
            presentation::http::shares::CreateShareResponse,
            presentation::http::shares::CreateShareMountRequest,
            presentation::http::shares::ShareItem,
            presentation::http::shares::ShareDocumentResponse,
            presentation::http::shares::ShareBrowseTreeItem,
            presentation::http::shares::ShareBrowseResponse,
            presentation::http::shares::ApplicableShareItem,
            presentation::http::shares::ActiveShareItem,
            presentation::http::shares::ShareMountItem,
            presentation::http::shares::MaterializeResponse,
            presentation::http::public::PublishResponse,
            presentation::http::public::PublicDocumentSummary,
            presentation::http::git::GitConfigResponse,
            presentation::http::git::CreateGitConfigRequest,
            presentation::http::git::UpdateGitConfigRequest,
            presentation::http::git::GitStatus,
            presentation::http::git::GitSyncRequest,
            presentation::http::git::GitSyncResponse,
            presentation::http::git::GitChangeItem,
            presentation::http::git::GitChangesResponse,
            presentation::http::git::GitCommitItem,
            presentation::http::git::GitHistoryResponse,
            presentation::http::git::AddPatternsRequest,
            presentation::http::git::CheckIgnoredRequest,
            application::contracts::diff::TextDiffLineType,
            application::contracts::diff::TextDiffLine,
            application::contracts::diff::TextDiffResult,
            presentation::http::markdown::RenderOptionsPayload,
            presentation::http::markdown::PlaceholderItemPayload,
            presentation::http::workspaces::WorkspaceResponse,
            presentation::http::workspaces::CreateWorkspaceRequest,
            presentation::http::workspaces::WorkspaceMemberResponse,
            presentation::http::workspaces::UpdateMemberRoleRequest,
            presentation::http::workspaces::WorkspaceRoleResponse,
            presentation::http::workspaces::PermissionOverridePayload,
            presentation::http::workspaces::CreateWorkspaceRoleRequest,
            presentation::http::workspaces::UpdateWorkspaceRoleRequest,
            presentation::http::workspaces::SwitchWorkspaceResponse,
            presentation::http::workspaces::WorkspacePermissionsResponse,
            presentation::http::workspaces::WorkspaceInvitationResponse,
            presentation::http::workspaces::CreateWorkspaceInvitationRequest,
            presentation::http::workspaces::CreateWorkspaceRequest,
            presentation::http::markdown::RenderResponseBody,
            presentation::http::markdown::RenderRequest,
            presentation::http::markdown::RenderManyRequest,
            presentation::http::markdown::RenderManyResponse,
            presentation::http::plugins::ManifestItem,
            presentation::http::plugins::RecordsResponse,
            presentation::http::plugins::CreateRecordBody,
            presentation::http::plugins::UpdateRecordBody,
            presentation::http::plugins::KvValueResponse,
            presentation::http::plugins::KvValueBody,
            presentation::http::plugins::ExecBody,
            presentation::http::plugins::ExecResultResponse,
            presentation::http::plugins::InstallFromUrlBody,
            presentation::http::plugins::InstallResponse,
            presentation::http::plugins::UninstallBody,
            presentation::http::health::HealthResp,
            presentation::http::shortcuts::UserShortcutResponse,
            presentation::http::shortcuts::UpdateUserShortcutRequest,
        )),
        tags(
            (name = "Auth", description = "Authentication"),
            (name = "Documents", description = "Documents management"),
            (name = "Files", description = "File management"),
            (name = "Sharing", description = "Document sharing"),
            (name = "Public Documents", description = "Public pages"),
            (name = "Git", description = "Git integration"),
            (name = "Markdown", description = "Markdown rendering"),
            (name = "Plugins", description = "Plugins management & data APIs"),
            (name = "Health", description = "System health checks"),
        )
    )]
pub struct ApiDoc;

pub async fn build_api_router(cfg: &Config, ctx: AppContext) -> anyhow::Result<Router> {
    let cors = build_cors(cfg)?;

    // Ensure uploads dir exists even when using S3 backend (local staging is still required)
    if let Err(e) = tokio::fs::create_dir_all(&cfg.storage_root).await {
        tracing::warn!(error=?e, dir=%cfg.storage_root, "Failed to create uploads dir");
    }

    // Build upload router with state
    let upload_router = Router::new()
        .route("/*path", get(presentation::http::files::serve_upload))
        .with_state(ctx.clone());

    // Build API router
    let api_router = Router::new()
        .nest("/api", presentation::http::health::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::documents::routes(ctx.clone()),
        )
        .nest(
            "/api/auth",
            presentation::http::auth::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::shares::routes(ctx.clone()))
        .nest("/api", presentation::http::files::routes(ctx.clone()))
        .nest("/api", presentation::http::tags::routes(ctx.clone()))
        .nest("/api", presentation::http::git::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::markdown::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::plugins::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::api_tokens::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::storage_ingest::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::workspaces::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::shortcuts::routes(ctx.clone()),
        )
        .nest(
            "/api/public",
            presentation::http::public::routes(ctx.clone()),
        )
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::auth::request_status::middleware,
        ))
        .layer(cors)
        // Global body size limit for uploads (configurable)
        .layer(DefaultBodyLimit::max(cfg.upload_max_bytes))
        .layer(
            TraceLayer::new_for_http().make_span_with(|req: &http::Request<_>| {
                let method = req.method().clone();
                let uri = req.uri().clone();
                let matched = req
                    .extensions()
                    .get::<MatchedPath>()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                tracing::info_span!("http", %method, %uri, matched_path = %matched)
            }),
        );

    let metrics_router = Router::new()
        .route(
            "/metrics",
            get(presentation::http::metrics::metrics_handler),
        )
        .with_state(ctx.clone());
    let api_router = api_router.merge(metrics_router);

    let api_router = api_router.nest("/api/uploads", upload_router);

    Ok(api_router)
}

pub fn build_ws_router(ctx: AppContext) -> Router {
    Router::new()
        .route("/api/yjs/:id", get(presentation::ws::axum_ws_entry))
        .with_state(ctx.clone())
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::auth::request_status::middleware,
        ))
}

fn build_cors(cfg: &Config) -> anyhow::Result<CorsLayer> {
    let frontend_origin = if let Some(origin) = cfg.frontend_url.clone() {
        Some(HeaderValue::from_str(&origin).map_err(|_| {
            anyhow::anyhow!("FRONTEND_URL must be a valid origin (e.g., https://app.example.com)")
        })?)
    } else {
        None
    };

    let cors_allow_headers = [
        http::header::CONTENT_TYPE,
        http::header::AUTHORIZATION,
        http::header::HeaderName::from_static("x-workspace-id"),
    ];
    let cors_expose_headers = [http::header::WWW_AUTHENTICATE];
    let cors = if let Some(origin) = frontend_origin.clone() {
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ])
            .allow_headers(cors_allow_headers.clone())
            .expose_headers(cors_expose_headers.clone())
            .allow_credentials(true)
    } else {
        if cfg.is_production {
            // In production, FRONTEND_URL is mandatory (enforced earlier), but fallback defensively to deny all
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(HeaderValue::from_static(
                    "http://invalid",
                )))
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers(cors_allow_headers.clone())
                .expose_headers(cors_expose_headers.clone())
        } else {
            // Development convenience
            CorsLayer::new()
                .allow_origin(AllowOrigin::mirror_request())
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers(cors_allow_headers.clone())
                .expose_headers(cors_expose_headers.clone())
                .allow_credentials(true)
        }
    };
    Ok(cors)
}
