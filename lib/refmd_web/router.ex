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

  scope "/api" do
    pipe_through :api
    get "/openapi.json", OpenApiSpex.Plug.RenderSpec, []
  end

  # Public auth endpoints (no session required)
  scope "/api/auth", RefMDWeb do
    pipe_through :api

    get "/salt", AuthController, :salt
    post "/register", AuthController, :register
    post "/login", AuthController, :login
  end

  # Authenticated endpoints
  scope "/api", RefMDWeb do
    pipe_through [:api, :authenticated]

    # Auth
    get "/auth/me", AuthController, :me
    delete "/auth/session", AuthController, :logout

    # Devices
    post "/devices/pending", DeviceController, :create_pending
    post "/devices/pending/:id/approve", DeviceController, :approve

    # KDF migration
    post "/auth/kdf-migration", AuthController, :kdf_migration

    # Encryption
    post "/encryption/workspaces/:workspace_id/keys", EncryptionController, :create_workspace_key
    get "/encryption/workspaces/:workspace_id/keys", EncryptionController, :get_workspace_keys
    post "/encryption/workspaces/:workspace_id/kek-backup", EncryptionController, :create_kek_backup
    get "/encryption/workspaces/:workspace_id/kek-backup", EncryptionController, :get_kek_backup
    post "/encryption/setup-complete", EncryptionController, :setup_complete
  end

  # SPA fallback: serve index.html for all non-API routes
  scope "/", RefMDWeb do
    get "/*path", FallbackController, :index
  end
end
