# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

rrp_http_header_options = [
  http_1_options: [max_header_length: 16_384],
  http_2_options: [max_header_block_size: 16_384]
]

config :refmd,
  namespace: RefMD,
  ecto_repos: [RefMD.Repo],
  generators: [timestamp_type: :utc_datetime, binary_id: true],
  expected_cluster_size: 1

# Configure the endpoint
config :refmd, RefMDWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  http: rrp_http_header_options,
  render_errors: [
    formats: [json: RefMDWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: RefMD.PubSub,
  live_view: [signing_salt: "PWa1s9I4"]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Configure Oban job queue
config :refmd, Oban,
  repo: RefMD.Repo,
  queues: [default: 10],
  plugins: [
    {Oban.Plugins.Pruner, max_age: 60 * 60 * 24},
    {Oban.Plugins.Cron,
     crontab: [
       {"*/5 * * * *", RefMD.Workers.CleanupRrpChallenges},
       {"*/15 * * * *", RefMD.Workers.CleanupSessions},
       {"*/30 * * * *", RefMD.Workers.CleanupPluginPackageStorage},
       {"*/5 * * * *", RefMD.Workers.MarkOverdueKeyRotations},
       {"* * * * *", RefMD.Workers.DeliverSecurityMutationOutbox},
       {"0 * * * *", RefMD.Workers.KekRotationReminder},
       {"0 3 * * *", RefMD.Workers.CleanupInvitations}
     ]}
  ]

# Configure Swoosh mailer
config :refmd, RefMD.Mailer, adapter: Swoosh.Adapters.Local
config :swoosh, :api_client, false

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :refmd, RefMD.Encryption.RotationPolicy,
  kek_rotation_seconds: 90 * 24 * 60 * 60,
  dek_rotation_seconds: 90 * 24 * 60 * 60,
  identity_rotation_seconds: 90 * 24 * 60 * 60

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
