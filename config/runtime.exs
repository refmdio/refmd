import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

rrp_http_header_options = [
  http_1_options: [max_header_length: 16_384],
  http_2_options: [max_header_block_size: 16_384]
]

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/refmd start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :refmd, RefMDWeb.Endpoint, server: true
end

config :refmd, RefMDWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))] ++ rrp_http_header_options

require_env = fn name ->
  case System.get_env(name) do
    value when is_binary(value) and value != "" ->
      value

    _ ->
      raise "environment variable #{name} is missing."
  end
end

optional_env = fn name, default ->
  case System.get_env(name) do
    value when is_binary(value) and value != "" -> value
    _ -> default
  end
end

positive_integer_env = fn name, default ->
  case Integer.parse(optional_env.(name, Integer.to_string(default))) do
    {value, ""} when value > 0 -> value
    _ -> raise "environment variable #{name} must be a positive integer"
  end
end

config :refmd, RefMD.Encryption.RotationPolicy,
  kek_rotation_seconds: positive_integer_env.("REFMD_KEK_ROTATION_SECONDS", 90 * 24 * 60 * 60),
  dek_rotation_seconds: positive_integer_env.("REFMD_DEK_ROTATION_SECONDS", 90 * 24 * 60 * 60),
  identity_rotation_seconds:
    positive_integer_env.("REFMD_IDENTITY_ROTATION_SECONDS", 90 * 24 * 60 * 60)

storage_mode =
  if config_env() == :prod do
    require_env.("REFMD_STORAGE_MODE")
  else
    optional_env.("REFMD_STORAGE_MODE", "local")
  end

storage_config =
  case storage_mode do
    "local" ->
      local_base_path =
        if config_env() == :prod do
          require_env.("REFMD_STORAGE_LOCAL_BASE_PATH")
        else
          optional_env.(
            "REFMD_STORAGE_LOCAL_BASE_PATH",
            Path.join(System.tmp_dir!(), "refmd-storage")
          )
        end

      [
        mode: "local",
        local: [
          base_path: local_base_path
        ]
      ]

    "s3" ->
      [
        mode: "s3",
        s3: [
          endpoint: optional_env.("S3_ENDPOINT", "https://s3.amazonaws.com"),
          bucket: require_env.("S3_BUCKET"),
          access_key_id: require_env.("S3_ACCESS_KEY_ID"),
          secret_access_key: require_env.("S3_SECRET_ACCESS_KEY"),
          region: optional_env.("S3_REGION", "ap-northeast-1"),
          session_token: System.get_env("S3_SESSION_TOKEN"),
          path_style: System.get_env("S3_PATH_STYLE", "false") in ["1", "true", "TRUE"]
        ]
      ]

    _ ->
      raise "REFMD_STORAGE_MODE must be local or s3"
  end

config :refmd, :storage, storage_config

oauth_bool_env = fn name, default ->
  case System.get_env(name) do
    nil -> default
    value -> String.downcase(value) in ["1", "true", "yes", "on"]
  end
end

config :refmd, oauth_error_details: config_env() != :prod

if config_env() != :test do
  config :refmd, :oauth,
    google: [
      enabled: oauth_bool_env.("GOOGLE_OAUTH_ENABLED", true),
      client_id: System.get_env("GOOGLE_OAUTH_CLIENT_ID"),
      client_secret: System.get_env("GOOGLE_OAUTH_CLIENT_SECRET"),
      redirect_uri: System.get_env("GOOGLE_OAUTH_REDIRECT_URI")
    ],
    github: [
      enabled: oauth_bool_env.("GITHUB_OAUTH_ENABLED", true),
      client_id: System.get_env("GITHUB_OAUTH_CLIENT_ID"),
      client_secret: System.get_env("GITHUB_OAUTH_CLIENT_SECRET"),
      redirect_uri: System.get_env("GITHUB_OAUTH_REDIRECT_URI")
    ]
end

if config_env() == :prod do
  dummy_salt_secret =
    System.get_env("DUMMY_SALT_SECRET") ||
      raise """
      environment variable DUMMY_SALT_SECRET is missing.
      Generate a random 32+ character secret for dummy salt derivation.
      """

  config :refmd, dummy_salt_secret: dummy_salt_secret

  share_server_key_id = System.get_env("SHARE_SERVER_KEY_ID", "primary")
  share_server_key = System.get_env("SHARE_SERVER_KEY")
  share_server_keys_json = System.get_env("SHARE_SERVER_KEYS")

  share_server_keys =
    cond do
      is_binary(share_server_keys_json) and share_server_keys_json != "" ->
        case Jason.decode(share_server_keys_json) do
          {:ok, keys} when is_map(keys) and map_size(keys) > 0 ->
            keys

          _ ->
            raise "SHARE_SERVER_KEYS must be a non-empty JSON object of {key_id: base64url_key}"
        end

      is_binary(share_server_key) and share_server_key != "" ->
        %{share_server_key_id => share_server_key}

      true ->
        raise """
        environment variable SHARE_SERVER_KEY (or SHARE_SERVER_KEYS) is missing.
        Generate a random 32-byte server key for share envelope encryption.
        Example: SHARE_SERVER_KEY=$(openssl rand -base64 32 | tr -d '+/=' | tr '/+' '-_')
        """
    end

  Enum.each(share_server_keys, fn {kid, encoded} ->
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} when byte_size(decoded) == 32 ->
        :ok

      {:ok, decoded} ->
        raise "share_server_keys[#{kid}] must decode to 32 bytes (got #{byte_size(decoded)})"

      :error ->
        raise "share_server_keys[#{kid}] must be base64url-encoded"
    end
  end)

  unless Map.has_key?(share_server_keys, share_server_key_id) do
    raise "SHARE_SERVER_KEY_ID '#{share_server_key_id}' has no corresponding key in SHARE_SERVER_KEYS"
  end

  config :refmd,
    share_server_key_id: share_server_key_id,
    share_server_keys: share_server_keys

  cors_origins =
    case System.get_env("CORS_ORIGINS") do
      nil -> []
      origins -> String.split(origins, ",", trim: true)
    end

  config :refmd, cors_origins: cors_origins

  samesite_mode = System.get_env("SAMESITE_MODE", "lax")
  config :refmd, samesite_mode: samesite_mode

  config :refmd, cookie_secure: true

  trusted_proxies =
    case System.get_env("TRUSTED_PROXIES") do
      nil ->
        IO.warn(
          "TRUSTED_PROXIES not set. Behind a reverse proxy, all users share one rate limit bucket. " <>
            "Set TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12 to fix."
        )

        nil

      value ->
        String.split(value, ",", trim: true) |> Enum.map(&String.trim/1)
    end

  config :refmd, trusted_proxies: trusted_proxies

  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :refmd, RefMD.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :refmd,
    expected_cluster_size: System.get_env("EXPECTED_CLUSTER_SIZE", "1") |> String.to_integer(),
    token_secret_key_base: secret_key_base

  if cluster_service = System.get_env("CLUSTER_SERVICE_NAME") do
    config :libcluster,
      topologies: [
        refmd: [
          strategy: Cluster.Strategy.Kubernetes.DNS,
          config: [
            service: cluster_service,
            application_name: "refmd"
          ]
        ]
      ]
  end

  config :refmd, RefMDWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http:
      [
        # Enable IPv6 and bind on all interfaces.
        # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
        # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
        # for details about using IPv6 vs IPv4 and loopback vs public addresses.
        ip: {0, 0, 0, 0, 0, 0, 0, 0}
      ] ++ rrp_http_header_options,
    secret_key_base: secret_key_base

  if https_key = System.get_env("HTTPS_KEY_PATH") do
    config :refmd, RefMDWeb.Endpoint,
      https:
        [
          port: String.to_integer(System.get_env("HTTPS_PORT", "4443")),
          cipher_suite: :compatible,
          keyfile: https_key,
          certfile: System.get_env("HTTPS_CERT_PATH")
        ] ++ rrp_http_header_options
  end

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :refmd, RefMDWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :refmd, RefMDWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
