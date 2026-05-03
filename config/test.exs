import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :refmd, RefMD.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "refmd_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :refmd, RefMDWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "lrXu5GPXHMgzLRwuC3D3u3iHadwMAj/HWA+fUidwaDuBTvvAM05SdxFROCo4zZNb",
  server: false

# Dummy salt secret for consistent fake salts (non-existent users)
config :refmd, dummy_salt_secret: "test-dummy-salt-secret"

config :refmd,
  share_server_key_id: "test-share-key",
  share_server_keys: %{
    "test-share-key" => Base.url_encode64(:binary.copy(<<1>>, 32), padding: false)
  }

# Use Swoosh test adapter for in-process assertions
config :refmd, RefMD.Mailer, adapter: Swoosh.Adapters.Test

# Disable Oban in tests (no queues, no plugins)
config :refmd, Oban, testing: :manual

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
