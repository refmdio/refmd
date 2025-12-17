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
            presentation::http::identity::auth::register,
            presentation::http::identity::auth::login,
            presentation::http::identity::auth::oauth_state,
            presentation::http::identity::auth::oauth_login,
            presentation::http::identity::auth::list_oauth_providers,
            presentation::http::identity::auth::refresh_session,
            presentation::http::identity::auth::logout,
            presentation::http::identity::auth::me,
            presentation::http::identity::auth::list_sessions,
            presentation::http::identity::auth::revoke_session,
            presentation::http::identity::api_tokens::list_api_tokens,
            presentation::http::identity::api_tokens::create_api_token,
            presentation::http::identity::api_tokens::revoke_api_token,
            presentation::http::identity::shortcuts::get_user_shortcuts,
            presentation::http::identity::shortcuts::update_user_shortcuts,
            presentation::http::documents::tagging::list_tags,
            presentation::ws::documents::yjs::axum_ws_entry,
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
            presentation::http::documents::files::upload_file,
            presentation::http::documents::files::get_file,
            presentation::http::documents::files::get_file_by_name,
            presentation::http::documents::sharing::create_share,
            presentation::http::documents::sharing::delete_share,
            presentation::http::documents::sharing::list_document_shares,
            presentation::http::documents::sharing::validate_share_token,
            presentation::http::documents::sharing::browse_share,
            presentation::http::documents::sharing::list_active_shares,
            presentation::http::documents::sharing::create_share_mount,
            presentation::http::documents::sharing::list_share_mounts,
            presentation::http::documents::sharing::delete_share_mount,
            presentation::http::documents::sharing::list_applicable_shares,
            presentation::http::documents::sharing::materialize_folder_share,
            presentation::http::documents::publishing::publish_document,
            presentation::http::documents::publishing::unpublish_document,
            presentation::http::documents::publishing::get_publish_status,
            presentation::http::documents::publishing::list_workspace_public_documents,
            presentation::http::documents::publishing::get_public_by_workspace_and_id,
            presentation::http::documents::publishing::get_public_content_by_workspace_and_id,
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
            presentation::http::core::storage_ingest::enqueue_ingest_events,
            presentation::http::core::markdown::render_markdown,
            presentation::http::core::markdown::render_markdown_many,
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
            presentation::http::core::health::health,
        ),
        components(schemas(
            presentation::http::identity::auth::RegisterRequest,
            presentation::http::identity::auth::LoginRequest,
            presentation::http::identity::auth::LoginResponse,
            presentation::http::identity::auth::OAuthLoginRequest,
            presentation::http::identity::auth::OAuthStateResponse,
            presentation::http::identity::auth::UserResponse,
            presentation::http::identity::auth::WorkspaceMembershipResponse,
            presentation::http::identity::api_tokens::ApiTokenItem,
            presentation::http::identity::api_tokens::ApiTokenCreateRequest,
            presentation::http::identity::api_tokens::ApiTokenCreateResponse,
            presentation::http::documents::tagging::TagItem,
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
            presentation::http::documents::files::UploadFileResponse,
            presentation::http::documents::files::UploadFileMultipart,
            presentation::http::documents::sharing::CreateShareRequest,
            presentation::http::documents::sharing::CreateShareResponse,
            presentation::http::documents::sharing::CreateShareMountRequest,
            presentation::http::documents::sharing::ShareItem,
            presentation::http::documents::sharing::ShareDocumentResponse,
            presentation::http::documents::sharing::ShareBrowseTreeItem,
            presentation::http::documents::sharing::ShareBrowseResponse,
            presentation::http::documents::sharing::ApplicableShareItem,
            presentation::http::documents::sharing::ActiveShareItem,
            presentation::http::documents::sharing::ShareMountItem,
            presentation::http::documents::sharing::MaterializeResponse,
            presentation::http::documents::publishing::PublishResponse,
            presentation::http::documents::publishing::PublicDocumentSummary,
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
            application::core::dtos::TextDiffLineType,
            application::core::dtos::TextDiffLine,
            application::core::dtos::TextDiffResult,
            presentation::http::core::markdown::RenderOptionsPayload,
            presentation::http::core::markdown::PlaceholderItemPayload,
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
            presentation::http::core::markdown::RenderResponseBody,
            presentation::http::core::markdown::RenderRequest,
            presentation::http::core::markdown::RenderManyRequest,
            presentation::http::core::markdown::RenderManyResponse,
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
            presentation::http::core::health::HealthResp,
            presentation::http::identity::shortcuts::UserShortcutResponse,
            presentation::http::identity::shortcuts::UpdateUserShortcutRequest,
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
        .route("/*path", get(presentation::http::documents::files::serve_upload))
        .with_state(ctx.clone());

    // Build API router
    let api_router = Router::new()
        .nest("/api", presentation::http::core::health::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::documents::routes(ctx.clone()),
        )
        .nest(
            "/api/auth",
            presentation::http::identity::auth::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::documents::sharing::routes(ctx.clone()))
        .nest("/api", presentation::http::documents::files::routes(ctx.clone()))
        .nest("/api", presentation::http::documents::tagging::routes(ctx.clone()))
        .nest("/api", presentation::http::git::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::core::markdown::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::plugins::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::identity::api_tokens::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::core::storage_ingest::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::workspaces::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::identity::shortcuts::routes(ctx.clone()),
        )
        .nest(
            "/api/public",
            presentation::http::documents::publishing::routes(ctx.clone()),
        )
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            presentation::http::identity::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::identity::auth::request_status::middleware,
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
            get(presentation::http::core::metrics::metrics_handler),
        )
        .with_state(ctx.clone());
    let api_router = api_router.merge(metrics_router);

    let api_router = api_router.nest("/api/uploads", upload_router);

    Ok(api_router)
}

pub fn build_ws_router(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/api/yjs/:id",
            get(presentation::ws::documents::yjs::axum_ws_entry),
        )
        .with_state(ctx.clone())
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            presentation::http::identity::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::identity::auth::request_status::middleware,
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
