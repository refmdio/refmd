use axum::extract::{DefaultBodyLimit, MatchedPath};
use axum::{Router, middleware, routing::get};
use http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// Allow using the crate name `api::` in this module.
use crate as api;

use api::bootstrap::config::Config;
use api::presentation::context::AppContext;

#[derive(OpenApi)]
#[openapi(
        paths(
            api::presentation::http::auth::register,
            api::presentation::http::auth::login,
            api::presentation::http::auth::oauth_state,
            api::presentation::http::auth::oauth_login,
            api::presentation::http::auth::list_oauth_providers,
            api::presentation::http::auth::refresh_session,
            api::presentation::http::auth::logout,
            api::presentation::http::auth::me,
            api::presentation::http::auth::list_sessions,
            api::presentation::http::auth::revoke_session,
            api::presentation::http::api_tokens::list_api_tokens,
            api::presentation::http::api_tokens::create_api_token,
            api::presentation::http::api_tokens::revoke_api_token,
            api::presentation::http::shortcuts::get_user_shortcuts,
            api::presentation::http::shortcuts::update_user_shortcuts,
            api::presentation::http::tags::list_tags,
            api::presentation::ws::axum_ws_entry,
            api::presentation::http::documents::list_documents,
            api::presentation::http::documents::create_document,
            api::presentation::http::documents::get_document,
            api::presentation::http::documents::update_document,
            api::presentation::http::documents::duplicate_document,
            api::presentation::http::documents::delete_document,
            api::presentation::http::documents::get_document_content,
            api::presentation::http::documents::download_document,
            api::presentation::http::documents::list_document_snapshots,
            api::presentation::http::documents::get_document_snapshot_diff,
            api::presentation::http::documents::restore_document_snapshot,
            api::presentation::http::documents::download_document_snapshot,
            api::presentation::http::documents::search_documents,
            api::presentation::http::documents::get_backlinks,
            api::presentation::http::documents::get_outgoing_links,
            api::presentation::http::files::upload_file,
            api::presentation::http::files::get_file,
            api::presentation::http::files::get_file_by_name,
            api::presentation::http::shares::create_share,
            api::presentation::http::shares::delete_share,
            api::presentation::http::shares::list_document_shares,
            api::presentation::http::shares::validate_share_token,
            api::presentation::http::shares::browse_share,
            api::presentation::http::shares::list_active_shares,
            api::presentation::http::shares::create_share_mount,
            api::presentation::http::shares::list_share_mounts,
            api::presentation::http::shares::delete_share_mount,
            api::presentation::http::shares::list_applicable_shares,
            api::presentation::http::shares::materialize_folder_share,
            api::presentation::http::public::publish_document,
            api::presentation::http::public::unpublish_document,
            api::presentation::http::public::get_publish_status,
            api::presentation::http::public::list_workspace_public_documents,
            api::presentation::http::public::get_public_by_workspace_and_id,
            api::presentation::http::public::get_public_content_by_workspace_and_id,
            api::presentation::http::git::get_config,
            api::presentation::http::git::create_or_update_config,
            api::presentation::http::git::delete_config,
            api::presentation::http::git::get_status,
            api::presentation::http::git::get_changes,
            api::presentation::http::git::get_history,
            api::presentation::http::git::get_working_diff,
            api::presentation::http::git::get_commit_diff,
            api::presentation::http::git::sync_now,
            api::presentation::http::git::import_repository,
            api::presentation::http::git::start_pull_session,
            api::presentation::http::git::get_pull_session,
            api::presentation::http::git::resolve_pull_session,
            api::presentation::http::git::finalize_pull_session,
            api::presentation::http::git::init_repository,
            api::presentation::http::git::deinit_repository,
            api::presentation::http::git::ignore_document,
            api::presentation::http::git::ignore_folder,
            api::presentation::http::git::get_gitignore_patterns,
            api::presentation::http::git::add_gitignore_patterns,
            api::presentation::http::git::check_path_ignored,
            api::presentation::http::storage_ingest::enqueue_ingest_events,
            api::presentation::http::markdown::render_markdown,
            api::presentation::http::markdown::render_markdown_many,
            api::presentation::http::workspaces::list_workspaces,
            api::presentation::http::workspaces::create_workspace,
            api::presentation::http::workspaces::switch_workspace,
            api::presentation::http::workspaces::list_members,
            api::presentation::http::workspaces::update_member_role,
            api::presentation::http::workspaces::get_workspace_permissions,
            api::presentation::http::workspaces::list_roles,
            api::presentation::http::workspaces::create_role,
            api::presentation::http::workspaces::update_role,
            api::presentation::http::workspaces::delete_role,
            api::presentation::http::workspaces::list_invitations,
            api::presentation::http::workspaces::create_invitation,
            api::presentation::http::workspaces::accept_invitation,
            api::presentation::http::workspaces::download_workspace_archive,
            api::presentation::http::plugins::get_manifest,
            api::presentation::http::plugins::exec_action,
            api::presentation::http::plugins::list_records,
            api::presentation::http::plugins::create_record,
            api::presentation::http::plugins::update_record,
            api::presentation::http::plugins::delete_record,
            api::presentation::http::plugins::get_kv_value,
            api::presentation::http::plugins::put_kv_value,
            api::presentation::http::plugins::install_from_url,
            api::presentation::http::plugins::uninstall,
            api::presentation::http::plugins::sse_updates,
            api::presentation::http::health::health,
        ),
        components(schemas(
            api::presentation::http::auth::RegisterRequest,
            api::presentation::http::auth::LoginRequest,
            api::presentation::http::auth::LoginResponse,
            api::presentation::http::auth::OAuthLoginRequest,
            api::presentation::http::auth::OAuthStateResponse,
            api::presentation::http::auth::UserResponse,
            api::presentation::http::auth::WorkspaceMembershipResponse,
            api::presentation::http::api_tokens::ApiTokenItem,
            api::presentation::http::api_tokens::ApiTokenCreateRequest,
            api::presentation::http::api_tokens::ApiTokenCreateResponse,
            api::presentation::http::tags::TagItem,
            api::presentation::http::documents::Document,
            api::presentation::http::documents::DocumentListResponse,
            api::presentation::http::documents::CreateDocumentRequest,
            api::presentation::http::documents::UpdateDocumentRequest,
            api::presentation::http::documents::DuplicateDocumentRequest,
            api::presentation::http::documents::BacklinkInfo,
            api::presentation::http::documents::BacklinksResponse,
            api::presentation::http::documents::OutgoingLink,
            api::presentation::http::documents::OutgoingLinksResponse,
            api::presentation::http::documents::SearchResult,
            api::presentation::http::files::UploadFileResponse,
            api::presentation::http::files::UploadFileMultipart,
            api::presentation::http::shares::CreateShareRequest,
            api::presentation::http::shares::CreateShareResponse,
            api::presentation::http::shares::CreateShareMountRequest,
            api::presentation::http::shares::ShareItem,
            api::presentation::http::shares::ShareDocumentResponse,
            api::presentation::http::shares::ShareBrowseTreeItem,
            api::presentation::http::shares::ShareBrowseResponse,
            api::presentation::http::shares::ApplicableShareItem,
            api::presentation::http::shares::ActiveShareItem,
            api::presentation::http::shares::ShareMountItem,
            api::presentation::http::shares::MaterializeResponse,
            api::presentation::http::public::PublishResponse,
            api::presentation::http::public::PublicDocumentSummary,
            api::presentation::http::git::GitConfigResponse,
            api::presentation::http::git::CreateGitConfigRequest,
            api::presentation::http::git::UpdateGitConfigRequest,
            api::presentation::http::git::GitStatus,
            api::presentation::http::git::GitSyncRequest,
            api::presentation::http::git::GitSyncResponse,
            api::presentation::http::git::GitChangeItem,
            api::presentation::http::git::GitChangesResponse,
            api::presentation::http::git::GitCommitItem,
            api::presentation::http::git::GitHistoryResponse,
            api::presentation::http::git::AddPatternsRequest,
            api::presentation::http::git::CheckIgnoredRequest,
            api::application::dto::diff::TextDiffLineType,
            api::application::dto::diff::TextDiffLine,
            api::application::dto::diff::TextDiffResult,
            api::presentation::http::markdown::RenderOptionsPayload,
            api::presentation::http::markdown::PlaceholderItemPayload,
            api::presentation::http::workspaces::WorkspaceResponse,
            api::presentation::http::workspaces::CreateWorkspaceRequest,
            api::presentation::http::workspaces::WorkspaceMemberResponse,
            api::presentation::http::workspaces::UpdateMemberRoleRequest,
            api::presentation::http::workspaces::WorkspaceRoleResponse,
            api::presentation::http::workspaces::PermissionOverridePayload,
            api::presentation::http::workspaces::CreateWorkspaceRoleRequest,
            api::presentation::http::workspaces::UpdateWorkspaceRoleRequest,
            api::presentation::http::workspaces::SwitchWorkspaceResponse,
            api::presentation::http::workspaces::WorkspacePermissionsResponse,
            api::presentation::http::workspaces::WorkspaceInvitationResponse,
            api::presentation::http::workspaces::CreateWorkspaceInvitationRequest,
            api::presentation::http::workspaces::CreateWorkspaceRequest,
            api::presentation::http::markdown::RenderResponseBody,
            api::presentation::http::markdown::RenderRequest,
            api::presentation::http::markdown::RenderManyRequest,
            api::presentation::http::markdown::RenderManyResponse,
            api::presentation::http::plugins::ManifestItem,
            api::presentation::http::plugins::RecordsResponse,
            api::presentation::http::plugins::CreateRecordBody,
            api::presentation::http::plugins::UpdateRecordBody,
            api::presentation::http::plugins::KvValueResponse,
            api::presentation::http::plugins::KvValueBody,
            api::presentation::http::plugins::ExecBody,
            api::presentation::http::plugins::ExecResultResponse,
            api::presentation::http::plugins::InstallFromUrlBody,
            api::presentation::http::plugins::InstallResponse,
            api::presentation::http::plugins::UninstallBody,
            api::presentation::http::health::HealthResp,
            api::presentation::http::shortcuts::UserShortcutResponse,
            api::presentation::http::shortcuts::UpdateUserShortcutRequest,
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
        .route("/*path", get(api::presentation::http::files::serve_upload))
        .with_state(ctx.clone());

    // Build API router
    let api_router = Router::new()
        .nest("/api", api::presentation::http::health::routes(ctx.clone()))
        .nest(
            "/api",
            api::presentation::http::documents::routes(ctx.clone()),
        )
        .nest(
            "/api/auth",
            api::presentation::http::auth::routes(ctx.clone()),
        )
        .nest("/api", api::presentation::http::shares::routes(ctx.clone()))
        .nest("/api", api::presentation::http::files::routes(ctx.clone()))
        .nest("/api", api::presentation::http::tags::routes(ctx.clone()))
        .nest("/api", api::presentation::http::git::routes(ctx.clone()))
        .nest(
            "/api",
            api::presentation::http::markdown::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::plugins::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::api_tokens::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::storage_ingest::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::workspaces::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::shortcuts::routes(ctx.clone()),
        )
        .nest(
            "/api/public",
            api::presentation::http::public::routes(ctx.clone()),
        )
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            api::presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            api::presentation::http::auth::request_status::middleware,
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
            get(api::presentation::http::metrics::metrics_handler),
        )
        .with_state(ctx.clone());
    let api_router = api_router.merge(metrics_router);

    let api_router = api_router.nest("/api/uploads", upload_router);

    Ok(api_router)
}

pub fn build_ws_router(ctx: AppContext) -> Router {
    Router::new()
        .route("/api/yjs/:id", get(api::presentation::ws::axum_ws_entry))
        .with_state(ctx.clone())
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            api::presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            api::presentation::http::auth::request_status::middleware,
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
