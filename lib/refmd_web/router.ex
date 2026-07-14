defmodule RefMDWeb.Router do
  use RefMDWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug RefMDWeb.Plugs.RateLimit
    plug RefMDWeb.Plugs.StrictSecurityJson
    plug OpenApiSpex.Plug.PutApiSpec, module: RefMDWeb.ApiSpec
    plug RefMDWeb.Plugs.OpenApiRequestValidation
  end

  pipeline :authenticated do
    plug RefMDWeb.Plugs.RequireAuth
  end

  pipeline :session_authenticated do
    plug RefMDWeb.Plugs.RequireAuth, allow_share_participant: true
  end

  pipeline :identity_recovery_authenticated do
    plug RefMDWeb.Plugs.RequireAuth, allow_identity_recovery: true
  end

  pipeline :logout_authenticated do
    plug RefMDWeb.Plugs.RequireAuth,
      allow_share_participant: true,
      allow_identity_recovery: true
  end

  pipeline :share_session_authenticated do
    plug RefMDWeb.Plugs.RequireAuth, allow_share_participant: true, prefer_share_participant: true
  end

  pipeline :require_rrp do
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.RequireRrp
  end

  pipeline :session_require_rrp do
    plug RefMDWeb.Plugs.RequireAuth, allow_share_participant: true
    plug RefMDWeb.Plugs.RequireRrp, allow_share_participant: true
  end

  pipeline :verify_origin do
    plug RefMDWeb.Plugs.VerifyOrigin
  end

  pipeline :require_recovery_or_rrp do
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.RequireRecoveryOrRrp
  end

  pipeline :sandbox_document do
    plug RefMDWeb.Plugs.RateLimit
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.VerifyOrigin
  end

  pipeline :network_executor_session do
    plug RefMDWeb.Plugs.RateLimit
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.VerifyOrigin
  end

  scope "/api" do
    pipe_through :api
    get "/openapi.json", OpenApiSpex.Plug.RenderSpec, []
  end

  # Public endpoints (no session required)
  scope "/api/auth", RefMDWeb do
    pipe_through [:api, :verify_origin]

    get "/salt", AuthController, :salt
    post "/register", AuthController, :register
    post "/login", AuthController, :login
    get "/oauth/providers", AuthController, :oauth_providers
    post "/oauth/:provider/start", AuthController, :oauth_start
    post "/recovery/challenge", AuthController, :recovery_challenge
    post "/recovery/session", AuthController, :recovery_session
    post "/password-reset/request", PasswordController, :password_reset_request
    post "/password-reset/verify", PasswordController, :password_reset_verify
  end

  scope "/api/auth", RefMDWeb do
    pipe_through [:api]

    get "/oauth/:provider/callback", AuthController, :oauth_callback
  end

  scope "/.well-known", RefMDWeb do
    pipe_through [:api]

    get "/device-bound-sessions", AuthController, :dbsc_well_known
  end

  scope "/api/auth/dbsc", RefMDWeb do
    pipe_through [:api, :authenticated]

    post "/register", AuthController, :dbsc_register
  end

  scope "/api/auth/dbsc", RefMDWeb do
    pipe_through [:api]

    post "/refresh", AuthController, :dbsc_refresh
  end

  scope "/api/auth/dbsc/share", RefMDWeb do
    pipe_through [:api, :share_session_authenticated]

    post "/register", AuthController, :dbsc_share_register
  end

  scope "/api/auth/dbsc/share", RefMDWeb do
    pipe_through [:api]

    post "/refresh", AuthController, :dbsc_share_refresh
  end

  scope "/api/auth/dbsc/mount", RefMDWeb do
    pipe_through [:api]

    post "/register", AuthController, :dbsc_mount_register
    post "/refresh", AuthController, :dbsc_mount_refresh
  end

  scope "/api/shares", RefMDWeb do
    pipe_through [:api]

    get "/:share_slug", ShareController, :show
    get "/:share_slug/challenge", ShareController, :challenge
    get "/d/:document_token", ShareController, :document
    get "/f/:folder_token", ShareController, :folder
  end

  scope "/api/public", RefMDWeb do
    pipe_through [:api]

    get "/authors/:author_slug", PublicDocumentController, :show_author
    get "/authors/:author_slug/documents/:document_slug", PublicDocumentController, :show_public
  end

  scope "/api/shares", RefMDWeb do
    pipe_through [:api, :verify_origin]

    post "/:share_slug/bootstrap", ShareController, :bootstrap
    post "/:share_slug/challenge", ShareController, :respond_challenge
    post "/d/:document_token/bootstrap", ShareController, :document_bootstrap
    post "/f/:folder_token/bootstrap", ShareController, :folder_bootstrap
  end

  scope "/api/guest", RefMDWeb do
    pipe_through [:api, :verify_origin]

    post "/redeem", GuestInvitationController, :redeem
  end

  scope "/api/invitations", RefMDWeb do
    pipe_through [:api, :verify_origin]

    get "/lookup", InvitationController, :lookup
  end

  # Plugin acquisition/update and sandbox arming are user-device RRP protected.
  scope "/api", RefMDWeb do
    pipe_through [:api, :require_rrp, :verify_origin]

    post "/workspaces/:workspace_id/plugin-packages",
         PluginManagementController,
         :create_candidate

    post "/plugin-packages",
         PluginManagementController,
         :create_user_candidate

    post "/plugin-candidates",
         PluginManagementController,
         :create_manifest_routed_candidate

    post "/plugin-candidates/:candidate_id/approval",
         PluginManagementController,
         :promote_candidate_resource

    post "/workspaces/:workspace_id/plugin-runtime/:application_id/sandbox-documents",
         PluginRuntimeController,
         :create_sandbox_document
  end

  # Session-only endpoints (no RRP required, Origin-verified for CSRF defense)
  scope "/api", RefMDWeb do
    pipe_through [:api, :identity_recovery_authenticated, :verify_origin]

    get "/auth/me", AuthController, :me
    get "/auth/recovery", AuthController, :get_recovery
    post "/devices/registrations/challenge", DeviceController, :registration_challenge
    post "/devices/registrations", DeviceController, :create_registration
  end

  scope "/api", RefMDWeb do
    pipe_through [:api, :logout_authenticated, :verify_origin]

    post "/auth/logout", AuthController, :logout
  end

  scope "/api", RefMDWeb do
    pipe_through [:api, :authenticated, :verify_origin]

    # Auth
    get "/auth/external-accounts", AuthController, :external_accounts
    get "/auth/key-restore", AuthController, :key_restore
    post "/auth/oauth/crypto-setup", AuthController, :oauth_crypto_setup
    post "/auth/verify-key", AuthController, :verify_key
    post "/auth/kdf-migration", AuthController, :kdf_migration
    post "/auth/password-set", PasswordController, :password_set

    # Device (bootstrap, registration, listing, status polling)
    post "/devices/bootstrap/challenge", DeviceController, :bootstrap_challenge
    post "/devices/bootstrap", DeviceController, :bootstrap
    get "/devices/registrations", DeviceController, :list_registrations
    get "/devices/registrations/:device_id/sas", DeviceController, :get_registration_sas
    delete "/devices/registrations/:device_id", DeviceController, :reject_registration
    get "/workspaces/ids", EncryptionController, :workspace_ids

    # Encryption setup (initial, before RRP is possible)
    post "/encryption/setup-complete", EncryptionController, :setup_complete

    # Workspace creation is session-authenticated; the request carries the signed initial directory.
    post "/workspaces", WorkspaceController, :create

    # Share mounts
    post "/mounts", ShareMountController, :create
    get "/shares/:share_slug/mounts", ShareMountController, :share_mounts_for_share

    # Settings (read: session only, no RRP needed for startup)
    get "/settings", SettingsController, :show
  end

  scope "/api", RefMDWeb do
    pipe_through [:api, :session_authenticated, :verify_origin]

    post "/auth/rrp-challenge", AuthController, :rrp_challenge
    post "/auth/ws-token", AuthController, :ws_token

    get "/devices/registrations/:device_id/initial-ake-offers",
        DeviceController,
        :initial_ake_offers

    post "/devices/registrations/:device_id/initial-ake-responses",
         DeviceController,
         :initial_ake_responses
  end

  scope "/api", RefMDWeb do
    pipe_through [:api, :session_require_rrp, :verify_origin]

    get "/users/:user_id/key-directory/latest", KeyDirectoryController, :latest_user

    get "/workspaces/:workspace_id/key-directory/latest",
        KeyDirectoryController,
        :latest_workspace
  end

  # Recovery-or-RRP endpoints
  scope "/api", RefMDWeb do
    pipe_through [:api, :require_recovery_or_rrp, :verify_origin]

    post "/devices/registrations/:device_id/approve", DeviceController, :approve
  end

  # RRP-required endpoints
  scope "/api", RefMDWeb do
    pipe_through [:api, :require_rrp, :verify_origin]

    # Auth (RRP required)
    post "/auth/oauth/:provider/link/start", AuthController, :oauth_link_start
    delete "/auth/external-accounts/:provider", AuthController, :unlink_external_account
    post "/auth/password/setup", PasswordController, :password_setup
    patch "/auth/password", PasswordController, :change_password
    put "/auth/recovery-key", PasswordController, :regenerate_recovery_key

    get "/encryption/identity-rotation", IdentityRotationController, :status
    post "/encryption/identity-rotation/prepare", IdentityRotationController, :prepare
    post "/encryption/identity-rotation/activate", IdentityRotationController, :activate
    post "/encryption/identity-rotation/finalize", IdentityRotationController, :finalize

    # Settings (write: RRP required)
    patch "/settings", SettingsController, :update

    # Invitation mutations and member admission require the current device proof.
    post "/workspaces/invitations/accept", InvitationController, :accept
    post "/invitations/delivery-attempts", InvitationController, :create_delivery_attempt
    get "/invitations/delivery-attempts/:attempt_id", InvitationController, :show_delivery_attempt

    post "/workspaces/invitations/delivery-attempts/:attempt_id/consume",
         InvitationController,
         :consume_delivery_attempt

    post "/workspaces/:workspace_id/invitations", InvitationController, :create

    get "/workspaces/:workspace_id/invitation-delivery-attempts",
        InvitationController,
        :delivery_attempts

    post "/workspaces/:workspace_id/invitation-delivery-attempts/:attempt_id/approve",
         InvitationController,
         :approve_delivery_attempt

    get "/workspaces/:workspace_id/invitations/recipient",
        InvitationController,
        :resolve_recipient

    delete "/workspaces/:workspace_id/invitations/:invitation_id", InvitationController, :delete

    post "/workspaces/:workspace_id/guest-invitations", GuestInvitationController, :create
    post "/guest/redeem-known", GuestInvitationController, :redeem_known

    post "/guest/invitations/delivery-attempts/:attempt_id/consume",
         GuestInvitationController,
         :consume_delivery_attempt

    get "/workspaces/:workspace_id/guest-invitations/recipient",
        GuestInvitationController,
        :resolve_recipient

    delete "/workspaces/:workspace_id/guest-invitations/:invitation_id",
           GuestInvitationController,
           :delete

    # Key directory
    post "/workspaces/:workspace_id/key-directory/append", KeyDirectoryController, :append

    # Documents
    get "/documents", DocumentController, :index
    post "/documents", DocumentController, :create
    patch "/documents/reorder", DocumentController, :reorder
    get "/documents/:document_id", DocumentController, :show
    patch "/documents/:document_id", DocumentController, :update
    delete "/documents/:document_id", DocumentController, :delete
    post "/documents/:document_id/archive", DocumentController, :archive
    post "/documents/:document_id/unarchive", DocumentController, :unarchive
    post "/documents/:document_id/read-only/enable", DocumentController, :enable_read_only
    post "/documents/:document_id/read-only/disable", DocumentController, :disable_read_only
    post "/documents/:document_id/write-disable", DocumentController, :disable_writes_by_policy
    get "/documents/:document_id/shares", DocumentShareController, :index
    post "/documents/:document_id/shares", DocumentShareController, :create
    patch "/documents/:document_id/shares/:share_id", DocumentShareController, :update

    patch "/documents/:document_id/shares/:share_id/exclusions",
          DocumentShareController,
          :update_exclusions

    patch "/documents/:document_id/shares/:share_id/keys",
          DocumentShareController,
          :update_keys

    delete "/documents/:document_id/shares/:share_id", DocumentShareController, :delete

    get "/documents/:document_id/share-verification-directory",
        DocumentShareController,
        :verification_directory

    delete "/documents/:document_id/shares/:share_id/admin",
           DocumentShareController,
           :admin_delete

    post "/documents/:document_id/publication", PublicDocumentController, :create
    get "/documents/:document_id/publication", PublicDocumentController, :show
    patch "/documents/:document_id/publication", PublicDocumentController, :update
    delete "/documents/:document_id/publication", PublicDocumentController, :delete
    put "/documents/:document_id/publication/content", PublicDocumentController, :update_content
    get "/mounts", ShareMountController, :index
    get "/mounts/:mount_id", ShareMountController, :show

    post "/mounts/:mount_id/documents/:document_token/bootstrap",
         ShareMountController,
         :document_bootstrap

    post "/mounts/:mount_id/folders/:folder_token/bootstrap",
         ShareMountController,
         :folder_bootstrap

    get "/mounts/:mount_id/challenge", ShareMountController, :challenge

    # Workspaces
    get "/workspaces", WorkspaceController, :index
    get "/workspaces/:workspace_id", WorkspaceController, :show
    patch "/workspaces/:workspace_id", WorkspaceController, :update
    patch "/workspaces/:workspace_id/features", WorkspaceController, :update_features
    delete "/workspaces/:workspace_id", WorkspaceController, :delete

    get "/security/notifications", SecurityNotificationController, :index
    patch "/security/notifications/:notification_id/read", SecurityNotificationController, :read

    patch "/security/notifications/:notification_id/dismiss",
          SecurityNotificationController,
          :dismiss

    get "/workspaces/:workspace_id/plugin-runtime",
        PluginRuntimeController,
        :index

    get "/workspaces/:workspace_id/plugin-runtime/consent-required",
        PluginManagementController,
        :consent_required

    get "/workspaces/:workspace_id/plugin-applications",
        PluginManagementController,
        :index_plugins

    post "/workspaces/:workspace_id/plugin-applications",
         PluginManagementController,
         :apply_plugin

    get "/plugin-activations",
        PluginManagementController,
        :index_activations

    patch "/plugin-activations/:activation_id",
          PluginManagementController,
          :update_activation

    delete "/plugin-activations/:activation_id",
           PluginManagementController,
           :delete_activation

    get "/workspaces/:workspace_id/plugin-packages",
        PluginManagementController,
        :index_workspace_packages

    get "/plugin-packages",
        PluginManagementController,
        :index_user_packages

    get "/plugin-candidates/:candidate_id",
        PluginManagementController,
        :show_candidate_resource

    patch "/workspaces/:workspace_id/plugin-applications/:application_id",
          PluginManagementController,
          :update_plugin

    delete "/workspaces/:workspace_id/plugin-applications/:application_id",
           PluginManagementController,
           :delete_plugin

    post "/workspaces/:workspace_id/plugin-applications/:application_id/consent-events",
         PluginManagementController,
         :append_consent

    get "/workspaces/:workspace_id/plugin-runtime/:application_id/storage/:surface",
        PluginStorageController,
        :show

    get "/workspaces/:workspace_id/plugin-runtime/:application_id/bundle",
        PluginRuntimeController,
        :removed_bundle_endpoint

    post "/workspaces/:workspace_id/plugin-runtime-audit",
         PluginRuntimeController,
         :audit

    put "/workspaces/:workspace_id/plugin-runtime/:application_id/storage/:surface",
        PluginStorageController,
        :upsert

    delete "/workspaces/:workspace_id/plugin-runtime/:application_id/storage/:surface",
           PluginStorageController,
           :delete

    post "/workspaces/:workspace_id/plugin-runtime/:application_id/records/:surface",
         PluginStorageController,
         :create_record

    get "/workspaces/:workspace_id/plugin-runtime/:application_id/records/:surface/:record_id",
        PluginStorageController,
        :show_record

    delete "/workspaces/:workspace_id/plugin-runtime/:application_id/records/:surface/:record_id",
           PluginStorageController,
           :delete_record

    # Members
    get "/workspaces/:workspace_id/members", MemberController, :index
    get "/workspaces/:workspace_id/members/:user_id/devices", MemberController, :devices
    get "/workspaces/:workspace_id/member-keys", MemberController, :identity_keys
    patch "/workspaces/:workspace_id/members/:user_id", MemberController, :update
    delete "/workspaces/:workspace_id/members/:user_id", MemberController, :delete

    # Invitations
    get "/workspaces/:workspace_id/invitations", InvitationController, :index
    get "/workspaces/:workspace_id/guest-invitations", GuestInvitationController, :index

    # Roles
    get "/workspaces/:workspace_id/roles", RoleController, :index
    post "/workspaces/:workspace_id/roles", RoleController, :create
    patch "/workspaces/:workspace_id/roles/:role_id", RoleController, :update
    delete "/workspaces/:workspace_id/roles/:role_id", RoleController, :delete

    # Devices (RRP required)
    get "/devices", DeviceController, :list

    get "/devices/:device_id/initial-ake-responses",
        DeviceController,
        :initial_ake_response_status

    patch "/devices/:device_id", DeviceController, :rename
    delete "/devices/:device_id", DeviceController, :revoke

    # UMK distribution (RRP required)
    post "/devices/:device_id/keys/umk", UmkController, :distribute_umk
    get "/devices/:device_id/keys/umk", UmkController, :get_umk

    # Share mounts
    patch "/mounts/:mount_id", ShareMountController, :update
    delete "/mounts/:mount_id", ShareMountController, :delete
    post "/mounts/:mount_id/challenge", ShareMountController, :respond_challenge

    # Encryption (DEK operations)
    get "/encryption/documents/:document_id/keys", DocumentKeyController, :get_document_keys

    get "/encryption/documents/:document_id/keys/rotation-targets",
        DocumentKeyController,
        :get_rotation_targets

    get "/encryption/documents/:document_id/keys/rotation-completion",
        DocumentKeyController,
        :prepare_dek_rotation_completion

    post "/encryption/documents/:document_id/keys/rotation-completion",
         DocumentKeyController,
         :complete_dek_rotation

    get "/encryption/documents/:document_id/keys/wipe-requirement",
        DocumentKeyController,
        :get_document_wipe_requirement

    post "/encryption/documents/:document_id/keys/wipe-requirement/acknowledge",
         DocumentKeyController,
         :acknowledge_document_wipe

    post "/encryption/documents/:document_id/keys", DocumentKeyController, :create_document_key

    put "/encryption/documents/:document_id/keys/kek-rotation-rewrap",
        DocumentKeyController,
        :rewrap_document_key_for_kek_rotation

    # Encryption (KEK operations)
    post "/encryption/workspaces/:workspace_id/keys", EncryptionController, :create_workspace_key
    get "/encryption/workspaces/:workspace_id/keys", EncryptionController, :get_workspace_keys

    # KEK Rotation
    post "/encryption/workspaces/:workspace_id/kek-rotation",
         KekRotationController,
         :start_kek_rotation

    get "/encryption/workspaces/:workspace_id/kek-rotation/completion-manifest",
        KekRotationController,
        :prepare_kek_rotation_completion

    post "/encryption/workspaces/:workspace_id/kek-rotation/complete",
         KekRotationController,
         :complete_kek_rotation

    get "/encryption/workspaces/:workspace_id/kek-rotation/wipe-requirement",
        KekRotationController,
        :get_workspace_wipe_requirement

    post "/encryption/workspaces/:workspace_id/kek-rotation/wipe-requirement/acknowledge",
         KekRotationController,
         :acknowledge_workspace_wipe

    post "/encryption/workspaces/:workspace_id/member-envelopes",
         KekRotationController,
         :save_member_envelopes

    get "/encryption/workspaces/:workspace_id/member-envelope",
        KekRotationController,
        :get_member_envelope
  end

  scope "/api", RefMDWeb do
    pipe_through [:sandbox_document]

    get "/plugin-runtime/sandbox-documents/:session_id",
        PluginRuntimeController,
        :show_sandbox_document
  end

  if Application.compile_env(:refmd, :dev_routes) do
    scope "/dev" do
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  scope "/" do
    get "/health", RefMDWeb.HealthController, :index
  end

  scope "/api", RefMDWeb do
    pipe_through [:network_executor_session]

    post "/plugin-network-executor-sessions", PluginNetworkExecutorController, :create_session
  end

  scope "/", RefMDWeb do
    get "/plugin-network-executor", PluginNetworkExecutorController, :show
  end

  scope "/", RefMDWeb do
    get "/@:author_slug", PublicPageController, :show_author
    get "/@:author_slug/:document_slug", PublicPageController, :show
  end

  # SPA fallback: serve index.html for all non-API routes
  scope "/", RefMDWeb do
    get "/*path", FallbackController, :index
  end
end
