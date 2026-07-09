defmodule RefMDWeb.AuthControllerTest do
  use RefMDWeb.ConnCase, async: false

  alias RefMD.Auth
  alias RefMD.Auth.DBSC
  alias RefMD.Auth.OAuth
  alias RefMD.Crypto.Hash
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Users.User

  defmodule OAuthProviderPlug do
    import Plug.Conn

    def init(opts), do: opts

    def call(%Plug.Conn{method: "POST", request_path: "/github/token"} = conn, opts) do
      {:ok, body, conn} = read_body(conn)
      send(opts[:test_pid], {:github_token_request, URI.decode_query(body)})

      json(conn, 200, %{"access_token" => "github-controller-access-token"})
    end

    def call(%Plug.Conn{method: "GET", request_path: "/github/user"} = conn, opts) do
      send(opts[:test_pid], :github_user_request)
      json(conn, 200, %{"id" => 424_242, "login" => "controller-oauth"})
    end

    def call(%Plug.Conn{method: "GET", request_path: "/github/emails"} = conn, opts) do
      send(opts[:test_pid], :github_emails_request)

      json(conn, 200, [
        %{
          "email" => "Controller-OAuth@Example.com",
          "primary" => true,
          "verified" => true
        }
      ])
    end

    def call(conn, _opts), do: send_resp(conn, 404, "not found")

    defp json(conn, status, body) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, Jason.encode!(body))
    end
  end

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: "registered"
    })

    user_id
  end

  defp create_device(user_id) do
    device_id = Ecto.UUID.generate()
    keys = hybrid_device_material(device_id)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        id: device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: keys.public,
        signing_key_id: keys.signing_key_id,
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        client_nonce: client_nonce
      })

    device
  end

  defp create_login_keys(user_id, auth_key \\ nil) do
    recovery = recovery_authorization_material(user_id)
    identity_public_key = get_or_create_identity_public_key!(user_id)

    {:ok, _master_key} =
      Encryption.create_user_encrypted_master_key(%{
        user_id: user_id,
        auth_type: "password",
        encrypted_umk: <<1::256>>,
        umk_nonce: <<2::192>>,
        salt: <<3::128>>,
        kdf_type: "argon2id",
        kdf_params: %{"memory" => 65_536, "iterations" => 3, "parallelism" => 1},
        auth_key_hash: auth_key_hash(auth_key),
        recovery_encrypted_umk: <<4::256>>,
        recovery_nonce: <<5::192>>,
        recovery_authorization_public_material: recovery.public,
        recovery_authorization_key_id: recovery.key_id
      })

    {:ok, _identity_key} =
      Encryption.create_user_encrypted_identity_key(%{
        user_id: user_id,
        encrypted_identity_hybrid_encryption_private_key_material: <<7::256>>,
        identity_hybrid_encryption_private_key_material_nonce: <<8::192>>,
        encryption_key_id: identity_public_key.encryption_key_id,
        encrypted_identity_hybrid_signing_private_key_material: <<11::256>>,
        identity_hybrid_signing_private_key_material_nonce: <<12::192>>,
        signing_key_id: identity_public_key.signing_key_id
      })
  end

  defp auth_key_hash(nil), do: "auth-key-hash"
  defp auth_key_hash(auth_key), do: Bcrypt.hash_pwd_salt(auth_key)

  defp get_or_create_identity_public_key!(user_id) do
    case Encryption.get_user_identity_public_key(user_id) do
      nil ->
        identity_private = hybrid_signing_private_key_material("identity", user_id)
        identity_public = hybrid_signing_public_key_material(identity_private)
        {x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
        encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

        {:ok, identity_public_key} =
          Encryption.create_user_identity_public_key(%{
            user_id: user_id,
            hybrid_encryption_public_key_material: encryption.public,
            hybrid_signing_public_key_material: identity_public,
            pending_registration_challenge_hash: Hash.blake3_base64url("challenge")
          })

        identity_public_key

      identity_public_key ->
        identity_public_key
    end
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device.id})

    put_req_header(
      conn,
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
  end

  test "OAuth callback accepts provider callback query parameters", %{conn: conn} do
    conn =
      get(conn, "/api/auth/oauth/google/callback", %{
        "code" => "provider-code",
        "state" => "provider-state",
        "scope" => "openid email profile",
        "authuser" => "0",
        "prompt" => "none",
        "iss" => "https://accounts.google.com",
        "provider_extra" => "provider-owned"
      })

    assert json_response(conn, 401)["error"] == "invalid_oauth_state"
  end

  test "OAuth callback success creates session, DBSC registration, and safe redirect", %{
    conn: conn
  } do
    provider_server =
      start_supervised!(
        {Bandit,
         plug: {OAuthProviderPlug, test_pid: self()},
         scheme: :http,
         ip: {127, 0, 0, 1},
         port: 0,
         startup_log: false}
      )

    {:ok, {_ip, provider_port}} = ThousandIsland.listener_info(provider_server)
    provider_base_url = "http://127.0.0.1:#{provider_port}"
    oauth_config = Application.get_env(:refmd, :oauth)
    on_exit(fn -> Application.put_env(:refmd, :oauth, oauth_config) end)

    Application.put_env(
      :refmd,
      :oauth,
      Keyword.put(oauth_config, :github,
        client_id: "controller-github-client",
        client_secret: "controller-github-secret",
        authorization_endpoint: "#{provider_base_url}/github/authorize",
        token_endpoint: "#{provider_base_url}/github/token",
        userinfo_endpoint: "#{provider_base_url}/github/user",
        emails_endpoint: "#{provider_base_url}/github/emails"
      )
    )

    redirect_uri = "http://www.example.com/api/auth/oauth/github/callback"

    {:ok, authorization_url} =
      OAuth.start_authorization("github", redirect_uri, "https://evil.test")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    conn =
      get(conn, "/api/auth/oauth/github/callback", %{
        "code" => "controller-code",
        "state" => authorization_params["state"]
      })

    assert redirected_to(conn, 302) == "/"

    session_cookie = conn.resp_cookies["__Host-refmd-session"]
    assert session_cookie.value
    assert session_cookie.path == "/"
    assert session_cookie.secure
    assert session_cookie.http_only

    assert {:ok, session} = Auth.get_valid_session_by_token_base64(session_cookie.value)
    user = Users.get_user_by_email("controller-oauth@example.com")
    assert session.user_id == user.id
    refute session.remember_me

    registration_header = get_resp_header(conn, "secure-session-registration") |> List.first()
    assert registration_header =~ "challenge="
    assert registration_header =~ "authorization="

    external_account = Users.get_user_external_account("github", "424242")
    assert external_account.user_id == user.id

    assert_received {:github_token_request, token_form}
    assert token_form["code"] == "controller-code"
    assert token_form["client_secret"] == "controller-github-secret"
    assert token_form["redirect_uri"] == redirect_uri
    assert_received :github_user_request
    assert_received :github_emails_request
  end

  test "OAuth start returns safe provider configuration diagnostics", %{conn: conn} do
    oauth_config = Application.get_env(:refmd, :oauth)

    on_exit(fn -> Application.put_env(:refmd, :oauth, oauth_config) end)

    Application.put_env(:refmd, :oauth,
      google: [client_id: "test-google-client"],
      github: [
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    response =
      conn
      |> post("/api/auth/oauth/google/start", %{"return_to" => "/"})
      |> json_response(422)

    assert response["error"] == "oauth_provider_not_configured"
    assert response["details"] == %{"provider" => "google", "missing" => "client_secret"}
  end

  test "OAuth providers endpoint returns only enabled configured providers", %{conn: conn} do
    oauth_config = Application.get_env(:refmd, :oauth)

    on_exit(fn -> Application.put_env(:refmd, :oauth, oauth_config) end)

    Application.put_env(:refmd, :oauth,
      google: [
        enabled: true,
        client_id: "test-google-client",
        client_secret: "test-google-secret"
      ],
      github: [
        enabled: true,
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    assert conn
           |> get("/api/auth/oauth/providers")
           |> json_response(200) == %{"providers" => ["google", "github"]}

    Application.put_env(:refmd, :oauth,
      google: [
        enabled: true,
        client_id: "test-google-client",
        client_secret: nil
      ],
      github: [
        enabled: true,
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    assert conn
           |> recycle_with_rate_limit_bypass()
           |> get("/api/auth/oauth/providers")
           |> json_response(200) == %{"providers" => ["github"]}

    Application.put_env(:refmd, :oauth,
      google: [
        enabled: true,
        client_id: "test-google-client",
        client_secret: nil
      ],
      github: [
        enabled: false,
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    assert conn
           |> recycle_with_rate_limit_bypass()
           |> get("/api/auth/oauth/providers")
           |> json_response(200) == %{"providers" => []}
  end

  test "disabled OAuth providers cannot start authorization", %{conn: conn} do
    oauth_config = Application.get_env(:refmd, :oauth)

    on_exit(fn -> Application.put_env(:refmd, :oauth, oauth_config) end)

    Application.put_env(:refmd, :oauth,
      google: [
        enabled: false,
        client_id: "test-google-client",
        client_secret: "test-google-secret"
      ],
      github: [
        enabled: true,
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    response =
      conn
      |> post("/api/auth/oauth/google/start", %{"return_to" => "/"})
      |> json_response(422)

    assert response["error"] == "oauth_provider_disabled"
  end

  test "OAuth crypto setup stores oauth key material for first device bootstrap", %{conn: conn} do
    user_id = create_user("oauth-setup@example.com")
    {:ok, _settings} = Users.create_user_settings(user_id)
    {:ok, _workspace} = RefMD.Workspaces.create_default_workspace(user_id, "OAuth Workspace")

    {:ok, _external_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "google-oauth-setup",
        email: "oauth-setup@example.com"
      })

    {:ok, _session, token} = Auth.create_session(user_id)

    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> post("/api/auth/oauth/crypto-setup", oauth_crypto_setup_params(user_id))

    response = json_response(conn, 200)
    assert response["workspace_id"]
    assert response["workspace_owner_role_id"]

    master_key = Encryption.get_user_encrypted_master_key(user_id)
    assert master_key.auth_type == "oauth"
    refute master_key.encrypted_umk
    refute master_key.umk_nonce
    assert master_key.recovery_encrypted_umk

    identity_public_key = Encryption.get_user_identity_public_key(user_id)
    assert identity_public_key.hybrid_signing_public_key_material["owner_id"] == user_id
    assert Encryption.get_user_encrypted_identity_key(user_id)

    challenge_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> post("/api/devices/bootstrap/challenge")

    assert json_response(challenge_conn, 200)["registration_challenge"]
  end

  test "login rejects legacy _refmd request body auth inputs", %{conn: conn} do
    user_id = create_user("legacy-login-body@example.com")
    auth_key = "valid-auth-key"
    create_login_keys(user_id, auth_key)

    conn =
      post(conn, "/api/auth/login", %{
        "email" => "legacy-login-body@example.com",
        "auth_key" => auth_key,
        "_refmd_session" => "legacy-cookie-value"
      })

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "me returns only key restore metadata and key restore returns the key blob", %{conn: conn} do
    user_id = create_user("auth-controller@example.com")
    device = create_device(user_id)
    create_login_keys(user_id)

    conn = authed_conn(conn, user_id, device)

    me_response =
      conn
      |> get("/api/auth/me")
      |> json_response(200)

    refute Map.has_key?(me_response, "keys")
    assert me_response["key_restore_available"] == true
    assert me_response["key_restore_endpoint_ref"] == "auth-key-restore-v1"

    restore_response =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{get_session_cookie(conn)}")
      |> get("/api/auth/key-restore")
      |> json_response(200)

    assert restore_response["encrypted_umk"]
    assert restore_response["umk_nonce"]
    assert restore_response["encrypted_identity_hybrid_encryption_private_key_material"]
    assert restore_response["identity_encryption_key_id"]
    assert restore_response["encrypted_identity_hybrid_signing_private_key_material"]
    assert restore_response["identity_signing_key_id"]
  end

  test "DBSC register stores a binding and returns session instructions", %{conn: conn} do
    user_id = create_user("dbsc-register@example.com")
    {:ok, session, token} = Auth.create_session(user_id)
    {proof, _private_key, _challenge} = dbsc_registration_proof(session)

    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> put_req_header("secure-session-response", proof)
      |> post("/api/auth/dbsc/register")

    response = json_response(conn, 200)
    assert response["session_identifier"]
    assert response["refresh_url"] == "/api/auth/dbsc/refresh"
    assert [%{"name" => "__Host-refmd-session", "type" => "cookie"}] = response["credentials"]
    {_challenge, session_identifier} = dbsc_challenge(conn)
    assert session_identifier == response["session_identifier"]
    assert conn.resp_cookies["__Host-refmd-session"].path == "/"
    assert conn.resp_cookies["__Host-refmd-session"].secure
    assert conn.resp_cookies["__Host-refmd-session"].http_only
  end

  test "DBSC refresh rotates the canonical session cookie after proof verification", %{conn: conn} do
    user_id = create_user("dbsc-refresh@example.com")
    {:ok, session, token} = Auth.create_session(user_id)
    {registration_proof, private_key, _challenge} = dbsc_registration_proof(session)

    register_conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> put_req_header("secure-session-response", registration_proof)
      |> post("/api/auth/dbsc/register")

    registration = json_response(register_conn, 200)
    {challenge, session_identifier} = dbsc_challenge(register_conn)
    assert session_identifier == registration["session_identifier"]
    refresh_proof = dbsc_refresh_proof(private_key, challenge)

    refresh_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("sec-secure-session-id", registration["session_identifier"])
      |> put_req_header("secure-session-response", refresh_proof)
      |> post("/api/auth/dbsc/refresh")

    refreshed = json_response(refresh_conn, 200)
    assert refreshed["session_identifier"] == registration["session_identifier"]
    assert refresh_conn.resp_cookies["__Host-refmd-session"].value

    assert refresh_conn.resp_cookies["__Host-refmd-session"].value !=
             register_conn.resp_cookies["__Host-refmd-session"].value
  end

  test "DBSC-bound user sessions replace the canonical session cookie", %{
    conn: conn
  } do
    user_id = create_user("dbsc-required@example.com")
    {:ok, session, token} = Auth.create_session(user_id)
    {registration_proof, _private_key, _public_key} = dbsc_registration_proof(session)
    session_cookie = Base.url_encode64(token, padding: false)

    register_conn =
      conn
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> put_req_header("secure-session-response", registration_proof)
      |> post("/api/auth/dbsc/register")

    dbsc_session_cookie = register_conn.resp_cookies["__Host-refmd-session"].value

    stale_session_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> get("/api/auth/me")

    assert json_response(stale_session_conn, 401)["error"] == "unauthorized"

    authed_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{dbsc_session_cookie}")
      |> get("/api/auth/me")

    assert json_response(authed_conn, 200)["user_id"] == user_id
  end

  test "DBSC well-known policy advertises the first-party origin", %{conn: conn} do
    conn = get(conn, "/.well-known/device-bound-sessions")

    response = json_response(conn, 200)
    assert response["registering_origins"] == ["http://www.example.com"]
    assert response["relying_origins"] == ["http://www.example.com"]
    assert response["provider_origin"] == "http://www.example.com"
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  defp get_session_cookie(conn) do
    conn
    |> get_req_header("cookie")
    |> List.first()
    |> String.replace_prefix("__Host-refmd-session=", "")
  end

  defp recycle_with_rate_limit_bypass(conn) do
    conn
    |> recycle()
    |> put_req_header("x-refmd-e2e-rate-limit-bypass", "1")
  end

  defp oauth_crypto_setup_params(user_id) do
    recovery = recovery_authorization_material(user_id)
    identity_private = hybrid_signing_private_key_material("identity", user_id)
    identity_public = hybrid_signing_public_key_material(identity_private)
    {x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

    %{
      recovery_encrypted_umk: b64(<<4::256>>),
      recovery_nonce: b64(<<5::192>>),
      recovery_authorization_public_material: recovery.public,
      recovery_authorization_key_id: recovery.key_id,
      hybrid_encryption_public_key_material: encryption.public,
      hybrid_signing_public_key_material: identity_public,
      encrypted_identity_hybrid_encryption_private_key_material: b64(<<7::256>>),
      identity_hybrid_encryption_private_key_material_nonce: b64(<<8::192>>),
      encrypted_identity_hybrid_signing_private_key_material: b64(<<11::256>>),
      identity_hybrid_signing_private_key_material_nonce: b64(<<12::192>>)
    }
  end

  defp dbsc_registration_proof(session) do
    {:ok, registration_header} =
      DBSC.registration_header("user", session.id, "/api/auth/dbsc/register")

    challenge = registration_param!(registration_header, "challenge")
    authorization = registration_param!(registration_header, "authorization")
    {public_key, private_key, jwk} = dbsc_key_pair()

    proof =
      dbsc_proof(
        private_key,
        %{"alg" => "ES256", "typ" => "dbsc+jwt", "jwk" => jwk},
        %{"jti" => challenge, "authorization" => authorization}
      )

    {proof, private_key, public_key}
  end

  defp dbsc_refresh_proof(private_key, challenge) do
    dbsc_proof(
      private_key,
      %{"alg" => "ES256", "typ" => "dbsc+jwt"},
      %{"jti" => challenge}
    )
  end

  defp dbsc_key_pair do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :prime256v1)
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key

    jwk = %{
      "kty" => "EC",
      "crv" => "P-256",
      "x" => Base.url_encode64(x, padding: false),
      "y" => Base.url_encode64(y, padding: false)
    }

    {public_key, private_key, jwk}
  end

  defp dbsc_proof(private_key, header, payload) do
    signing_input = base64url_json(header) <> "." <> base64url_json(payload)

    signature =
      :ecdsa
      |> :crypto.sign(:sha256, signing_input, [private_key, :prime256v1])
      |> der_ecdsa_to_raw()
      |> Base.url_encode64(padding: false)

    signing_input <> "." <> signature
  end

  defp registration_param!(header, key) do
    [_, value] = Regex.run(~r/#{key}="([^"]+)"/, header)
    value
  end

  defp dbsc_challenge(conn) do
    header =
      conn
      |> get_resp_header("secure-session-challenge")
      |> List.first()

    [_, challenge, session_identifier] = Regex.run(~r/^"([^"]+)";id="([^"]+)"$/, header)
    {challenge, session_identifier}
  end

  defp b64(value), do: Base.url_encode64(value, padding: false)

  defp base64url_json(value), do: value |> Jason.encode!() |> Base.url_encode64(padding: false)

  defp der_ecdsa_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>) do
    r = binary_part(rest, 0, r_len)
    rest = binary_part(rest, r_len, byte_size(rest) - r_len)
    <<0x02, s_len, s::binary-size(s_len)>> = rest
    pad_ecdsa_integer(r) <> pad_ecdsa_integer(s)
  end

  defp pad_ecdsa_integer(value) do
    value = value |> :binary.bin_to_list() |> Enum.drop_while(&(&1 == 0)) |> :binary.list_to_bin()

    cond do
      byte_size(value) > 32 -> binary_part(value, byte_size(value) - 32, 32)
      byte_size(value) < 32 -> :binary.copy(<<0>>, 32 - byte_size(value)) <> value
      true -> value
    end
  end
end
