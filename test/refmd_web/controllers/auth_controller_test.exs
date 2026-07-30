defmodule RefMDWeb.AuthControllerTest do
  use RefMDWeb.ConnCase, async: false

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Auth.DBSC
  alias RefMD.Auth.OAuth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Devices.DeviceRegistration
  alias RefMD.Encryption
  alias RefMD.Encryption.{KeyDirectory, RecoverableIdentitySecretRecord}
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.AuditChainEvent
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

  defp create_device_with_signing_key(user_id) do
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

    %{device: device, signing_private_key: keys.private}
  end

  defp create_login_keys(user_id, auth_key \\ nil) do
    recovery = recovery_authorization_material(user_id)

    {identity_public_key, identity_private, identity_encryption_public} =
      get_or_create_identity_public_key!(user_id)

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
      user_id
      |> recoverable_identity_secret_record(
        identity_public_key.signing_key_id,
        identity_public_key.encryption_key_id,
        <<11::256>>,
        <<12::192>>,
        <<7::256>>,
        <<8::192>>
      )
      |> RecoverableIdentitySecretRecord.to_attrs!(%{
        user_id: user_id,
        signing_key_id: identity_public_key.signing_key_id,
        encryption_key_id: identity_public_key.encryption_key_id
      })
      |> Encryption.create_user_encrypted_identity_key()

    %{
      identity_private: identity_private,
      identity_encryption_public: identity_encryption_public
    }
  end

  defp install_signed_user_genesis!(user_id, identity_private) do
    identity = Encryption.get_user_identity_public_key(user_id)

    attrs = %{
      event_id: Ecto.UUID.generate(),
      class: "authority",
      type: "user.device.genesis_bootstrapped",
      event_body: %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "event_type" => "user.device.genesis_bootstrapped",
        "mutation_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "user",
        "chain_scope_id" => user_id,
        "actor" => %{"kind" => "identity", "user_id" => user_id},
        "subject_kind" => "account",
        "subject_id" => user_id,
        "canonical_request_hash" => Hash.blake3_base64url("auth-controller-request"),
        "key_directory_effects_hash" => Hash.blake3_base64url("auth-controller-effects")
      },
      actor: %{
        "user_id" => user_id,
        "device_id" => nil,
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => user_id
      },
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "user", "id" => user_id, "version_hash" => nil},
      action: %{
        "operation" => "user.device.genesis_bootstrapped",
        "result" => "completed",
        "reason_code" => nil
      },
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }

    event_hash =
      %{
        event_id: attrs.event_id,
        chain_scope_kind: "user",
        chain_scope_id: user_id,
        sequence: 1,
        previous_event_hash: "GENESIS",
        event_type: attrs.type,
        event_body: attrs.event_body
      }
      |> AuditChainEvent.build!()
      |> AuditChainEvent.hash!()

    payload = %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "user",
      "chain_scope_id" => user_id,
      "sequence" => 1,
      "event_hash" => event_hash,
      "signer_user_id" => user_id,
      "signing_key_id" => identity.signing_key_id,
      "authorization_checkpoint_scope_kind" => "user",
      "authorization_checkpoint_scope_id" => user_id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => "user.device.genesis_bootstrapped"
    }

    transcript =
      Audit.build_audit_checkpoint_transcript!("user_identity", "identity", user_id, payload)

    envelope = %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "audit_checkpoint",
          transcript,
          identity_private,
          identity.hybrid_signing_public_key_material
        ),
      "checkpoint_hash" => Audit.checkpoint_hash!("user_identity", payload)
    }

    assert {:ok, _result} =
             Security.record_signed_audit_events([attrs], envelope, [],
               genesis_candidate_authority: %{
                 chain_scope_kind: "user",
                 chain_scope_id: user_id,
                 signer_user_id: user_id,
                 signer_device_id: nil,
                 public_key_material: identity.hybrid_signing_public_key_material
               }
             )
  end

  defp create_oauth_master_key(user_id) do
    recovery = recovery_authorization_material(user_id)

    {:ok, _master_key} =
      Encryption.create_user_encrypted_master_key(%{
        user_id: user_id,
        auth_type: "oauth",
        recovery_encrypted_umk: <<4::256>>,
        recovery_nonce: <<5::192>>,
        recovery_authorization_public_material: recovery.public,
        recovery_authorization_key_id: recovery.key_id
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

        {identity_public_key, identity_private, encryption.public}

      identity_public_key ->
        {identity_public_key, nil, nil}
    end
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
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

  test "OAuth link start and callback attach GitHub without creating a new session", %{
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

    user_id = create_user("oauth-link@example.com")
    device = create_device_with_signing_key(user_id)

    {:ok, _google_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "controller-google-link",
        email: "oauth-link@example.com"
      })

    path = "/api/auth/oauth/github/link/start"
    body = %{"return_to" => "/dashboard?settings=account"}

    link_start_conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    authorization_url = json_response(link_start_conn, 200)["authorization_url"]

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    session_cookie = get_session_cookie(link_start_conn)

    callback_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> get("/api/auth/oauth/github/callback", %{
        "code" => "controller-code",
        "state" => authorization_params["state"]
      })

    assert redirected_to(callback_conn, 302) == "/dashboard?settings=account"
    refute callback_conn.resp_cookies["__Host-refmd-session"]

    external_account = Users.get_user_external_account_for_user(user_id, "github")
    assert external_account.provider_user_id == "424242"
    assert external_account.email == "controller-oauth@example.com"
  end

  test "OAuth account link callback rejects invalid DBSC-bound session cookie", %{
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

    user_id = create_user("oauth-link-dbsc@example.com")
    device = create_device_with_signing_key(user_id)

    {:ok, _google_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "controller-google-link-dbsc",
        email: "oauth-link-dbsc@example.com"
      })

    path = "/api/auth/oauth/github/link/start"
    body = %{"return_to" => "/dashboard?settings=account"}

    link_start_conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    authorization_url = json_response(link_start_conn, 200)["authorization_url"]

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    session = link_start_conn.private.test_session
    session_cookie = get_session_cookie(link_start_conn)
    {registration_proof, _private_key, _public_key} = dbsc_registration_proof(session)

    register_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> put_req_header("secure-session-response", registration_proof)
      |> post("/api/auth/dbsc/register")

    bound_session_cookie = register_conn.resp_cookies["__Host-refmd-session"].value

    from(b in RefMD.Auth.DBSCSessionBinding,
      where: b.session_kind == "user" and b.session_id == ^session.id
    )
    |> Repo.update_all(
      set: [credential_expires_at: DateTime.add(DateTime.utc_now(), -1, :second)]
    )

    callback_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{bound_session_cookie}")
      |> get("/api/auth/oauth/github/callback", %{
        "code" => "controller-code",
        "state" => authorization_params["state"]
      })

    assert json_response(callback_conn, 401)["error"] == "invalid_oauth_state"
    refute Users.get_user_external_account_for_user(user_id, "github")
    refute_received {:github_token_request, _token_form}
  end

  test "external account unlink rejects removing the last sign-in method", %{conn: conn} do
    user_id = create_user("last-method@example.com")
    device = create_device_with_signing_key(user_id)
    create_oauth_master_key(user_id)

    {:ok, _external_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "last-method-google",
        email: "last-method@example.com"
      })

    path = "/api/auth/external-accounts/google"

    response =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "DELETE",
        path,
        "",
        ""
      )
      |> delete(path)
      |> json_response(422)

    assert response["error"] == "last_auth_method_required"
    assert Users.get_user_external_account_for_user(user_id, "google")
  end

  test "external account unlink succeeds when password sign-in remains", %{conn: conn} do
    user_id = create_user("unlink-password@example.com")
    device = create_device_with_signing_key(user_id)
    create_login_keys(user_id, "valid-auth-key")

    {:ok, _external_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "unlink-password-google",
        email: "unlink-password@example.com"
      })

    path = "/api/auth/external-accounts/google"

    response =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "DELETE",
        path,
        "",
        ""
      )
      |> delete(path)
      |> json_response(200)

    assert response == %{"ok" => true}
    refute Users.get_user_external_account_for_user(user_id, "google")
  end

  test "password setup enables password login for an OAuth-only account", %{conn: conn} do
    user_id = create_user("oauth-password-setup@example.com")
    device = create_device_with_signing_key(user_id)
    create_oauth_master_key(user_id)

    {:ok, _external_account} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "oauth-password-google",
        email: "oauth-password-setup@example.com"
      })

    {:ok, _other_session, other_token} = Auth.create_session(user_id)

    path = "/api/auth/password/setup"

    body = %{
      "new_auth_key" => "new-auth-key",
      "new_salt" => Base.url_encode64(<<3::128>>, padding: false),
      "new_encrypted_umk" => Base.url_encode64(<<1::256>>, padding: false),
      "new_umk_nonce" => Base.url_encode64(<<2::192>>, padding: false)
    }

    conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 200) == %{"ok" => true}

    master_key = Encryption.get_user_encrypted_master_key(user_id)
    assert master_key.auth_type == "password"
    assert master_key.encrypted_umk == <<1::256>>
    assert master_key.umk_nonce == <<2::192>>
    assert master_key.salt == <<3::128>>

    assert {:ok, user} =
             Auth.verify_auth_key("oauth-password-setup@example.com", "new-auth-key")

    assert user.id == user_id

    assert {:error, :invalid_session} =
             Auth.get_valid_session_by_token_base64(
               Base.url_encode64(other_token, padding: false)
             )
  end

  test "removed OAuth crypto setup endpoint is unavailable", %{conn: conn} do
    conn = post(conn, "/api/auth/oauth/crypto-setup", %{})
    assert response(conn, 404)
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

  test "login routes an identity-wipe-required device to current recovery registration", %{
    conn: conn
  } do
    user_id = create_user("wipe-required-login@example.com")
    auth_key = "wipe-required-auth-key"
    create_login_keys(user_id, auth_key)
    %{device: device} = create_device_with_signing_key(user_id)

    device
    |> Ecto.Changeset.change(identity_wipe_required_at: DateTime.utc_now())
    |> Repo.update!()

    conn =
      post(conn, "/api/auth/login", %{
        "email" => "wipe-required-login@example.com",
        "auth_key" => auth_key,
        "device_id" => device.id
      })

    response = json_response(conn, 200)
    refute response["device_verified"]
    assert response["identity_recovery_required"]
    refute Map.has_key?(response, "keys")

    session = Repo.get!(RefMD.Auth.Session, response["session_id"])
    assert session.identity_recovery_required

    session_cookie = conn.resp_cookies["__Host-refmd-session"].value

    restricted_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> get("/api/settings")

    assert json_response(restricted_conn, 401) == %{"error" => "unauthorized"}

    allowed_conn =
      conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> get("/api/auth/me")

    assert json_response(allowed_conn, 200)["is_recovery"] == false

    logout_conn =
      allowed_conn
      |> recycle_with_rate_limit_bypass()
      |> put_req_header("cookie", "__Host-refmd-session=#{session_cookie}")
      |> post("/api/auth/logout")

    assert json_response(logout_conn, 200) == %{"ok" => true}
    assert logout_conn.resp_cookies["__Host-refmd-session"].max_age == 0
    assert {:error, _reason} = Auth.get_valid_session_by_token_base64(session_cookie)
  end

  test "websocket tokens reject sessions whose device requires identity wipe" do
    user_id = create_user("wipe-required-websocket@example.com")
    %{device: device} = create_device_with_signing_key(user_id)
    {:ok, session, _token} = Auth.create_session(user_id, %{device_id: device.id})
    ws_token = Auth.generate_ws_token(session.id)

    assert {:ok, ^user_id, _session} = Auth.verify_ws_token(ws_token)

    device
    |> Ecto.Changeset.change(identity_wipe_required_at: DateTime.utc_now())
    |> Repo.update!()

    assert {:error, :device_inactive} = Auth.verify_ws_token(ws_token)
  end

  test "me returns only key restore metadata and key restore returns the key blob", %{conn: conn} do
    user_id = create_user("auth-controller@example.com")
    login_keys = create_login_keys(user_id)
    device_material = create_device_with_signing_key(user_id)
    device = device_material.device

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        login_keys.identity_private,
        login_keys.identity_encryption_public,
        device_material.signing_private_key,
        device.hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "user",
      user_id,
      key_directory.user_events,
      key_directory.user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

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
    assert restore_response["identity_key_epoch"] == 1
    assert restore_response["identity_rotation_due_at"]
    assert restore_response["identity_key_checkpoint"]["payload"]["scope_kind"] == "user"
  end

  test "recovery bootstrap binds the verified user audit checkpoint", %{conn: conn} do
    user_id = create_user("recovery-audit-checkpoint@example.com")
    login_keys = create_login_keys(user_id)
    device_material = create_device_with_signing_key(user_id)
    device = device_material.device

    install_signed_user_genesis!(user_id, login_keys.identity_private)

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        login_keys.identity_private,
        login_keys.identity_encryption_public,
        device_material.signing_private_key,
        device.hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "user",
      user_id,
      key_directory.user_events,
      key_directory.user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    assert {:ok, %{audit_event: event}} =
             Security.record_audit_event(%{
               class: "authority",
               type: "recovery.started",
               actor: %{
                 "user_id" => user_id,
                 "device_id" => device.id,
                 "session_id" => nil,
                 "principal_kind" => "user",
                 "principal_id" => user_id
               },
               scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
               resource: %{"kind" => "credential", "id" => user_id, "version_hash" => nil},
               action: %{
                 "operation" => "recovery.started",
                 "result" => "completed",
                 "reason_code" => nil
               },
               sensitivity: Security.empty_sensitivity(),
               correlation: %{
                 "request_id" => nil,
                 "capability_id" => nil,
                 "execution_context_id" => nil,
                 "authority_event_ref" => nil
               }
             })

    response =
      conn
      |> authed_conn(user_id, device)
      |> get("/api/auth/recovery")
      |> json_response(200)

    assert %{
             "signed_checkpoint" => %{
               "payload" => %{
                 "chain_scope_kind" => "user",
                 "chain_scope_id" => ^user_id,
                 "sequence" => 1
               },
               "signature" => signature
             },
             "current_event_head" => %{
               "sequence" => event_sequence,
               "event_hash" => event_hash
             },
             "unsigned_tail" => [
               %{"sequence" => event_sequence, "event_hash" => event_hash}
             ]
           } = response["candidate_user_audit_checkpoint"]

    assert event_sequence == event.sequence
    assert event_hash == event.event_hash

    assert signature["signing_key_id"] ==
             Encryption.get_user_identity_public_key(user_id).signing_key_id
  end

  test "invalid recovery session rolls back its embedded target registration", %{conn: conn} do
    user_id = create_user("recovery-target-rollback@example.com")
    login_keys = create_login_keys(user_id)
    source_device_material = create_device_with_signing_key(user_id)
    source_device = source_device_material.device
    identity = Encryption.get_user_identity_public_key(user_id)

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        login_keys.identity_private,
        login_keys.identity_encryption_public,
        source_device_material.signing_private_key,
        source_device.hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "user",
      user_id,
      key_directory.user_events,
      key_directory.user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _x25519_private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)

    invalid_signature =
      Signature.__test_sign_hybrid_signature__(
        "recovery_session",
        Signature.build_recovery_session_transcript!(%{
          user_id: user_id,
          recipient_device_id: device_id,
          pending_registration_id: device_id,
          recovery_session_id: Ecto.UUID.generate(),
          server_challenge_hash: Hash.blake3_base64url("wrong-challenge"),
          recovered_identity_signing_key_id: identity.signing_key_id,
          recovery_authorization_key_id: Hash.blake3_base64url("wrong-recovery-key"),
          target_key_checkpoint_sequence: 1,
          target_key_checkpoint_hash: Hash.blake3_base64url("wrong-target-checkpoint"),
          candidate_user_checkpoint_sequence: 1,
          candidate_user_checkpoint_hash: Hash.blake3_base64url("wrong-candidate-checkpoint"),
          candidate_user_event_head_sequence: 1,
          candidate_user_event_head_hash: Hash.blake3_base64url("wrong-candidate-event"),
          candidate_user_audit_sequence: 1,
          candidate_user_audit_hash: Hash.blake3_base64url("wrong-audit"),
          recovery_capability_hash: Hash.blake3_base64url("wrong-capability"),
          pending_registration_binding_hash: Hash.blake3_base64url("wrong-binding")
        }),
        login_keys.identity_private,
        identity.hybrid_signing_public_key_material
      )

    params = %{
      "email" => "recovery-target-rollback@example.com",
      "recovery_session_id" => Ecto.UUID.generate(),
      "challenge" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      "recovery_session_signature" => invalid_signature,
      "recovery_authorization_key_id" => Hash.blake3_base64url("recovery-key"),
      "recovery_authorization_proof" => invalid_signature,
      "recovery_capability_hash" => Hash.blake3_base64url("capability"),
      "recovery_session_transcript_hash" => Hash.blake3_base64url("session"),
      "pending_registration_id" => device_id,
      "recipient_device_id" => device_id,
      "pending_registration_binding_hash" => Hash.blake3_base64url("binding"),
      "target_key_checkpoint_sequence" => 1,
      "target_key_checkpoint_hash" => Hash.blake3_base64url("target-checkpoint"),
      "candidate_user_checkpoint_sequence" => 1,
      "candidate_user_checkpoint_hash" => Hash.blake3_base64url("candidate-checkpoint"),
      "candidate_user_event_head_sequence" => 1,
      "candidate_user_event_head_hash" => Hash.blake3_base64url("candidate-event"),
      "candidate_user_checkpoint" => key_directory.user_checkpoint,
      "candidate_user_event_ancestry" => key_directory.user_events,
      "candidate_user_audit_sequence" => 1,
      "candidate_user_audit_hash" => Hash.blake3_base64url("audit"),
      "target_device_registration" => %{
        "device_id" => device_id,
        "name" => "Recovered browser",
        "device_type" => "browser",
        "identity_signing_key_id" => identity.signing_key_id,
        "device_hybrid_signing_public_key_material" => signing.public,
        "device_signing_key_id" => signing.signing_key_id,
        "device_hybrid_encryption_public_key_material" => encryption.public,
        "device_encryption_key_id" => encryption.encryption_key_id,
        "client_nonce" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      }
    }

    response = conn |> post("/api/auth/recovery/session", params) |> json_response(401)

    assert response["error"] == "invalid_or_expired_recovery_request"
    assert Repo.get(DeviceRegistration, device_id) == nil
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
