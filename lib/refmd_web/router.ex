defmodule RefMDWeb.Router do
  use RefMDWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug RefMDWeb.Plugs.RateLimit
    plug OpenApiSpex.Plug.PutApiSpec, module: RefMDWeb.ApiSpec
  end

  pipeline :authenticated do
    plug RefMDWeb.Plugs.RequireAuth
  end

  pipeline :require_pop do
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.RequirePoP
  end

  pipeline :sse do
    plug RefMDWeb.Plugs.RateLimit
  end

  pipeline :verify_origin do
    plug RefMDWeb.Plugs.VerifyOrigin
  end

  pipeline :require_recovery_or_pop do
    plug RefMDWeb.Plugs.RequireAuth
    plug RefMDWeb.Plugs.RequireRecoveryOrPoP
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
    post "/recovery/challenge", AuthController, :recovery_challenge
    post "/recovery/session", AuthController, :recovery_session
    post "/password-reset/request", AuthController, :password_reset_request
    post "/password-reset/verify", AuthController, :password_reset_verify
  end

  # SSE endpoints (no :api pipeline — EventSource sends Accept: text/event-stream, not json)
  # No Origin check — EventSource does not send Origin headers
  scope "/api", RefMDWeb do
    pipe_through [:sse, :authenticated]

    get "/devices/events", DeviceEventsController, :existing_device_events
    get "/devices/registrations/:device_id/events", DeviceEventsController, :pending_device_events
  end

  # Session-only endpoints (no PoP required, Origin-verified for CSRF defense)
  scope "/api", RefMDWeb do
    pipe_through [:api, :authenticated, :verify_origin]

    # Auth
    get "/auth/me", AuthController, :me
    post "/auth/logout", AuthController, :logout
    post "/auth/verify-key", AuthController, :verify_key
    post "/auth/pop-challenge", AuthController, :pop_challenge
    post "/auth/kdf-migration", AuthController, :kdf_migration
    get "/auth/recovery", AuthController, :get_recovery
    post "/auth/password-set", AuthController, :password_set

    # Device (bootstrap, registration, listing, status polling)
    post "/devices/bootstrap", DeviceController, :bootstrap
    post "/devices/registrations", DeviceController, :create_registration
    get "/devices/registrations", DeviceController, :list_registrations
    get "/devices/registrations/:id/sas", DeviceController, :get_registration_sas
    delete "/devices/registrations/:id", DeviceController, :reject_registration

    # Trust transfer (session-only: nonce request, state retrieval)
    post "/trust-transfer/nonce", TrustTransferController, :create_nonce
    get "/trust-transfer/state", TrustTransferController, :get_state

    # Encryption setup (initial, before PoP is possible)
    post "/encryption/setup-complete", EncryptionController, :setup_complete
  end

  # Recovery-or-PoP endpoints
  scope "/api", RefMDWeb do
    pipe_through [:api, :require_recovery_or_pop, :verify_origin]

    post "/devices/registrations/:id/approve", DeviceController, :approve
  end

  # PoP-required endpoints
  scope "/api", RefMDWeb do
    pipe_through [:api, :require_pop, :verify_origin]

    # Auth (PoP required)
    patch "/auth/password", AuthController, :change_password
    put "/auth/recovery-key", AuthController, :regenerate_recovery_key

    # Trust transfer (PoP required: state sending)
    post "/trust-transfer/state", TrustTransferController, :send_state

    # Workspaces (PoP required, minimal for Phase 2)
    get "/workspaces/ids", EncryptionController, :workspace_ids

    # Devices (PoP required)
    get "/devices", DeviceController, :list
    patch "/devices/:device_id", DeviceController, :rename
    delete "/devices/:device_id", DeviceController, :revoke

    # UMK distribution (PoP required)
    post "/devices/:device_id/keys/umk", EncryptionController, :distribute_umk
    get "/devices/:device_id/keys/umk", EncryptionController, :get_umk

    # Encryption (KEK/DEK operations)
    post "/encryption/workspaces/:workspace_id/keys", EncryptionController, :create_workspace_key
    get "/encryption/workspaces/:workspace_id/keys", EncryptionController, :get_workspace_keys

    post "/encryption/workspaces/:workspace_id/kek-backup",
         EncryptionController,
         :create_kek_backup

    get "/encryption/workspaces/:workspace_id/kek-backup", EncryptionController, :get_kek_backup

    # KEK Rotation
    post "/encryption/workspaces/:workspace_id/kek-rotation",
         EncryptionController,
         :start_kek_rotation

    post "/encryption/workspaces/:workspace_id/kek-rotation/complete",
         EncryptionController,
         :complete_kek_rotation

    post "/encryption/workspaces/:workspace_id/member-envelopes",
         EncryptionController,
         :save_member_envelopes

    get "/encryption/workspaces/:workspace_id/member-envelope",
        EncryptionController,
        :get_member_envelope

    get "/encryption/workspaces/:workspace_id/member-keys",
        EncryptionController,
        :get_workspace_member_keys
  end

  if Application.compile_env(:refmd, :dev_routes) do
    scope "/dev" do
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # SPA fallback: serve index.html for all non-API routes
  scope "/", RefMDWeb do
    get "/*path", FallbackController, :index
  end
end
