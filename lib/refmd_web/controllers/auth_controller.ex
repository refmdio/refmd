defmodule RefMDWeb.AuthController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Auth, Devices, Encryption, Security, Sharing, Users}
  alias RefMD.Auth.DBSC, as: AuthDBSC
  alias RefMD.Auth.Genesis
  alias RefMD.Auth.OAuth
  alias RefMD.Crypto.Hash
  alias RefMDWeb.Http.RrpSessionBinding
  alias RefMDWeb.Http.RrpTranscript
  alias RefMDWeb.Http.SessionCookies
  alias RefMDWeb.Payloads.DeviceRegistration, as: DeviceRegistrationPayload

  alias RefMDWeb.Schemas

  @target_kdf_params %{
    "algorithm" => "argon2id",
    "memory" => 65_536,
    "iterations" => 3,
    "parallelism" => 4,
    "hash_length" => 32
  }

  operation(:salt,
    summary: "Get salt for email",
    parameters: [
      email: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Salt response", "application/json", Schemas.SaltResponse}
    ]
  )

  def salt(conn, %{"email" => email}) do
    {master_key, salt} =
      case Auth.get_salt_for_email(email) do
        {:ok, nil, dummy_salt} -> {nil, dummy_salt}
        {:ok, master_key, salt} -> {master_key, salt}
      end

    kdf_params =
      if master_key && master_key.kdf_params do
        master_key.kdf_params
      else
        @target_kdf_params
      end

    json(conn, %{
      salt: Base.url_encode64(salt, padding: false),
      kdf_params: kdf_params
    })
  end

  operation(:register,
    summary: "Register a new user",
    request_body: {"Registration params", "application/json", Schemas.RegisterRequest},
    responses: [
      created: {"Registration response", "application/json", Schemas.RegisterResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def register(conn, params) do
    case Genesis.begin_password_registration(params) do
      {:ok, %{genesis: genesis, token: token}} ->
        max_age = max(DateTime.diff(genesis.expires_at, DateTime.utc_now(), :second), 1)

        conn
        |> SessionCookies.set_genesis_session_cookie(token, max_age)
        |> put_status(:created)
        |> json(%{
          bootstrap_required: true,
          registration_id: genesis.registration_id,
          reserved_user_id: genesis.reserved_user_id,
          reserved_workspace_id: genesis.reserved_workspace_id,
          reserved_workspace_role_ids: genesis.reserved_workspace_role_ids,
          expires_at: genesis.expires_at
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: registration_error(reason)})
    end
  end

  defp registration_error(:email_taken), do: "email_taken"
  defp registration_error(:invalid_email), do: "invalid_email"
  defp registration_error(:invalid_display_name), do: "invalid_display_name"
  defp registration_error(:account_genesis_conflict), do: "account_genesis_conflict"
  defp registration_error(_), do: "invalid_registration"

  operation(:login,
    summary: "Login with credentials",
    request_body: {"Login params", "application/json", Schemas.LoginRequest},
    responses: [
      ok: {"Login response", "application/json", Schemas.LoginResponse},
      unauthorized: {"Invalid credentials", "application/json", Schemas.ErrorResponse}
    ]
  )

  def login(conn, %{"auth_key" => auth_key, "email" => email} = params) do
    case Auth.verify_auth_key(email, auth_key) do
      {:ok, user} ->
        handle_successful_login(conn, user, params)

      {:error, :invalid_credentials} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_credentials"})
    end
  end

  operation(:oauth_providers,
    summary: "List enabled OAuth providers",
    responses: [
      ok: {"Enabled OAuth providers", "application/json", Schemas.OAuthProvidersResponse}
    ]
  )

  def oauth_providers(conn, _params) do
    json(conn, %{providers: OAuth.available_providers()})
  end

  operation(:oauth_start,
    summary: "Start OAuth authorization code flow",
    parameters: [
      provider: [
        in: :path,
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, enum: ["google", "github"]}
      ]
    ],
    request_body: {"OAuth start params", "application/json", Schemas.OAuthStartRequest},
    responses: [
      ok: {"OAuth authorization URL", "application/json", Schemas.OAuthStartResponse},
      unprocessable_entity: {"OAuth start failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def oauth_start(conn, %{"provider" => provider} = params) do
    return_to = safe_return_to(params["return_to"])
    redirect_uri = oauth_redirect_uri(conn, provider)

    case OAuth.start_authorization(provider, redirect_uri, return_to) do
      {:ok, authorization_url} ->
        json(conn, %{authorization_url: authorization_url})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(oauth_error_payload(reason))
    end
  end

  operation(:oauth_link_start,
    summary: "Start OAuth provider account linking",
    parameters: [
      provider: [
        in: :path,
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, enum: ["google", "github"]}
      ]
    ],
    request_body: {"OAuth link start params", "application/json", Schemas.OAuthStartRequest},
    responses: [
      ok: {"OAuth authorization URL", "application/json", Schemas.OAuthStartResponse},
      unprocessable_entity: {"OAuth link start failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def oauth_link_start(conn, %{"provider" => provider} = params) do
    return_to = safe_return_to(params["return_to"])
    redirect_uri = oauth_redirect_uri(conn, provider)
    session = conn.assigns.current_session

    case OAuth.start_account_link(
           provider,
           redirect_uri,
           return_to,
           conn.assigns.current_user_id,
           session.id
         ) do
      {:ok, authorization_url} ->
        json(conn, %{authorization_url: authorization_url})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(oauth_error_payload(reason))
    end
  end

  operation(:oauth_callback,
    summary: "Complete OAuth authorization code flow",
    parameters: [
      provider: [
        in: :path,
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, enum: ["google", "github"]}
      ],
      code: [in: :query, type: :string, required: false],
      state: [in: :query, type: :string, required: false],
      scope: [in: :query, type: :string, required: false],
      authuser: [in: :query, type: :string, required: false],
      prompt: [in: :query, type: :string, required: false],
      iss: [in: :query, type: :string, required: false],
      hd: [in: :query, type: :string, required: false],
      error: [in: :query, type: :string, required: false],
      error_description: [in: :query, type: :string, required: false],
      error_uri: [in: :query, type: :string, required: false]
    ],
    responses: [
      found: {"OAuth callback redirect", "text/html", %OpenApiSpex.Schema{type: :string}},
      unauthorized: {"OAuth callback failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def oauth_callback(conn, %{"provider" => provider, "state" => state, "code" => code}) do
    redirect_uri = oauth_redirect_uri(conn, provider)

    case OAuth.complete_callback(provider, state, code, redirect_uri,
           session_context: oauth_callback_session_context(conn)
         ) do
      {:ok, %{purpose: "login", user: user, return_to: return_to}} ->
        {:ok, session, token} =
          Auth.create_session(user.id, %{
            remember_me: false,
            ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
            user_agent: get_req_header(conn, "user-agent") |> List.first()
          })

        conn
        |> set_session_cookie(token, session.remember_me)
        |> put_registration_header(:user, session)
        |> redirect(to: safe_return_to(return_to))

      {:ok, %{purpose: "account_link", return_to: return_to}} ->
        redirect(conn, to: safe_return_to(return_to))

      {:error, reason} ->
        conn
        |> put_status(:unauthorized)
        |> json(oauth_error_payload(reason))
    end
  end

  def oauth_callback(conn, _params) do
    conn |> put_status(:unauthorized) |> json(%{error: "invalid_oauth_callback"})
  end

  operation(:dbsc_well_known,
    summary: "Get Device Bound Session Credentials policy",
    responses: [
      ok: {"DBSC well-known policy", "application/json", %OpenApiSpex.Schema{type: :object}}
    ]
  )

  def dbsc_well_known(conn, _params) do
    origin = origin(conn)

    conn
    |> put_dbsc_hardening_headers()
    |> json(%{
      registering_origins: [origin],
      relying_origins: [origin],
      provider_origin: origin
    })
  end

  operation(:dbsc_register,
    summary: "Register a user Device Bound Session Credentials binding",
    parameters: [
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC registration failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_register(conn, _params), do: handle_dbsc_register(conn, "user")

  operation(:dbsc_refresh,
    summary: "Refresh a user Device Bound Session Credentials cookie",
    parameters: [
      sec_secure_session_id: [
        in: :header,
        name: :"sec-secure-session-id",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ],
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC refresh failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_refresh(conn, _params), do: handle_dbsc_refresh(conn, "user")

  operation(:dbsc_share_register,
    summary: "Register a share participant Device Bound Session Credentials binding",
    parameters: [
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC registration failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_share_register(conn, _params), do: handle_dbsc_register(conn, "share_participant")

  operation(:dbsc_share_refresh,
    summary: "Refresh a share participant Device Bound Session Credentials cookie",
    parameters: [
      sec_secure_session_id: [
        in: :header,
        name: :"sec-secure-session-id",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ],
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC refresh failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_share_refresh(conn, _params), do: handle_dbsc_refresh(conn, "share_participant")

  operation(:dbsc_mount_register,
    summary: "Register a mount Device Bound Session Credentials binding",
    parameters: [
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC registration failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_mount_register(conn, _params), do: handle_dbsc_mount_register(conn)

  operation(:dbsc_mount_refresh,
    summary: "Refresh a mount Device Bound Session Credentials cookie",
    parameters: [
      sec_secure_session_id: [
        in: :header,
        name: :"sec-secure-session-id",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ],
      secure_session_response: [
        in: :header,
        name: :"secure-session-response",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string}
      ]
    ],
    responses: [
      ok: {"DBSC session instructions", "application/json", Schemas.DbscSessionInstructions},
      unauthorized: {"DBSC refresh failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def dbsc_mount_refresh(conn, _params),
    do: handle_dbsc_refresh(conn, "mount", &mount_dbsc_token/1)

  operation(:me,
    summary: "Get current session info",
    responses: [
      ok: {"Session info", "application/json", Schemas.MeResponse},
      unauthorized: {"Not authenticated", "application/json", Schemas.ErrorResponse}
    ]
  )

  def me(conn, _params) do
    if conn.assigns[:session_kind] == :share_participant do
      conn |> put_status(:unauthorized) |> json(%{error: "unauthorized"})
    else
      user = Users.get_user(conn.assigns.current_user_id)
      session = conn.assigns.current_session
      device_verified = conn.assigns.device_verified

      master_key = Encryption.get_user_encrypted_master_key(user.id)
      identity_pub = Encryption.get_user_identity_public_key(user.id)
      user_pin = Encryption.current_user_key_directory_pin(user.id)

      device_checkpoint = current_device_checkpoint(user.id, session.device_id)

      key_restore_available = device_verified and not is_nil(session.device_id)

      response = %{
        user_id: user.id,
        email: user.email,
        name: user.name,
        account_type: user.account_type,
        encryption_setup_at: user.encryption_setup_at,
        session_id: session.id,
        device_id: session.device_id,
        device_verified: device_verified,
        device_key_checkpoint_sequence: device_checkpoint.sequence,
        device_key_checkpoint_hash: device_checkpoint.hash,
        is_recovery: session.is_recovery,
        remember_me: session.remember_me,
        expires_at: session.expires_at,
        auth_type: master_key && master_key.auth_type,
        key_restore_available: key_restore_available,
        key_restore_endpoint_ref: if(key_restore_available, do: "auth-key-restore-v1", else: nil),
        candidate_user_event_head_sequence: user_pin && user_pin.event_head_sequence,
        identity_hybrid_encryption_public_key_material:
          identity_pub && identity_pub.hybrid_encryption_public_key_material,
        identity_hybrid_signing_public_key_material:
          identity_pub && identity_pub.hybrid_signing_public_key_material
      }

      json(conn, response)
    end
  end

  operation(:external_accounts,
    summary: "List external authentication methods for current user",
    responses: [
      ok:
        {"External authentication methods", "application/json", Schemas.ExternalAccountsResponse}
    ]
  )

  def external_accounts(conn, _params) do
    user_id = conn.assigns.current_user_id
    master_key = Encryption.get_user_encrypted_master_key(user_id)

    json(conn, %{
      accounts:
        user_id
        |> Users.get_user_external_accounts()
        |> Enum.map(&external_account_response/1),
      available_providers: OAuth.available_providers(),
      password_configured: password_master_key?(master_key)
    })
  end

  defp password_master_key?(%{auth_type: "password"}), do: true
  defp password_master_key?(_), do: false

  operation(:unlink_external_account,
    summary: "Unlink an external authentication provider",
    parameters: [
      provider: [
        in: :path,
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, enum: ["google", "github"]}
      ]
    ],
    responses: [
      ok: {"External account unlinked", "application/json", Schemas.OkResponse},
      not_found: {"External account missing", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Cannot unlink provider", "application/json", Schemas.ErrorResponse}
    ]
  )

  def unlink_external_account(conn, %{"provider" => provider}) do
    user_id = conn.assigns.current_user_id

    case Users.unlink_external_account_preserving_login(user_id, provider) do
      {:ok, :ok} ->
        json(conn, %{ok: true})

      {:error, :external_account_not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "external_account_not_found"})

      {:error, :last_auth_method_required} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "last_auth_method_required"})

      {:error, _reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "external_account_unlink_failed"})
    end
  end

  defp current_device_checkpoint(_user_id, nil), do: %{sequence: nil, hash: nil}

  defp current_device_checkpoint(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device ->
        %{sequence: device.key_checkpoint_sequence, hash: device.key_checkpoint_hash}

      _ ->
        %{sequence: nil, hash: nil}
    end
  end

  operation(:key_restore,
    summary: "Get current device key restore payload",
    responses: [
      ok: {"Key restore payload", "application/json", Schemas.LoginKeys},
      unauthorized: {"Not authenticated", "application/json", Schemas.ErrorResponse},
      forbidden: {"Device is not verified", "application/json", Schemas.ErrorResponse}
    ]
  )

  def key_restore(conn, _params) do
    cond do
      conn.assigns[:session_kind] == :share_participant ->
        conn |> put_status(:unauthorized) |> json(%{error: "unauthorized"})

      not conn.assigns.device_verified or is_nil(conn.assigns.current_session.device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "device_not_verified"})

      true ->
        keys =
          conn.assigns.current_user_id
          |> Encryption.get_login_keys(conn.assigns.current_session.device_id)
          |> format_login_keys()

        json(conn, keys)
    end
  end

  operation(:kdf_migration,
    summary: "Migrate KDF parameters",
    request_body: {"KDF migration params", "application/json", Schemas.KdfMigrationRequest},
    responses: [
      ok: {"Migration result", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Migration failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def kdf_migration(conn, params) do
    user_id = conn.assigns.current_user_id
    master_key = Encryption.get_user_encrypted_master_key(user_id)

    cond do
      params["new_kdf_params"] != @target_kdf_params ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_kdf_params"})

      master_key == nil ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "no_master_key"})

      master_key.kdf_params == @target_kdf_params ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "already_migrated"})

      true ->
        case Encryption.update_master_key_kdf(user_id, %{
               auth_key_hash: Bcrypt.hash_pwd_salt(params["new_auth_key"]),
               encrypted_umk: decode_optional_binary(params["new_encrypted_umk"]),
               umk_nonce: decode_optional_binary(params["new_nonce"]),
               kdf_params: params["new_kdf_params"]
             }) do
          {:ok, _} ->
            json(conn, %{ok: true})

          {:error, _} ->
            conn |> put_status(:unprocessable_entity) |> json(%{error: "migration_failed"})
        end
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:verify_key,
    summary: "Verify auth key without creating a session",
    request_body: {"Verify key params", "application/json", Schemas.VerifyKeyRequest},
    responses: [
      ok: {"Valid", "application/json", Schemas.OkResponse},
      unauthorized: {"Invalid credentials", "application/json", Schemas.ErrorResponse}
    ]
  )

  def verify_key(conn, %{"auth_key" => auth_key}) do
    user = Users.get_user(conn.assigns.current_user_id)
    session = conn.assigns.current_session

    case Auth.verify_auth_key(user.email, auth_key) do
      {:ok, _} ->
        Auth.update_session_verified_at(session.id)
        json(conn, %{ok: true})

      {:error, :invalid_credentials} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_credentials"})
    end
  end

  operation(:rrp_challenge,
    summary: "Request a RefMD Request Proof challenge nonce",
    parameters: [
      x_refmd_rrp_device_id: [
        in: :header,
        name: :"x-refmd-rrp-device-id",
        description: "RRP signing device id.",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, format: :uuid}
      ]
    ],
    responses: [
      ok: {"Challenge response", "application/json", Schemas.RrpChallengeResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  operation(:ws_token,
    summary: "Generate a short-lived WebSocket authentication token",
    responses: [
      ok: {"WS token", "application/json", Schemas.WsTokenResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse}
    ]
  )

  def ws_token(conn, _params) do
    session = conn.assigns.current_session

    token =
      case conn.assigns[:session_kind] do
        :share_participant -> Sharing.generate_ws_token(session.id)
        _ -> Auth.generate_ws_token(session.id)
      end

    json(conn, %{token: token})
  end

  def rrp_challenge(conn, _params) do
    device_id = get_req_header(conn, "x-refmd-rrp-device-id") |> List.first()

    case conn.assigns[:session_kind] do
      :share_participant -> create_share_rrp_challenge(conn, device_id)
      _ -> create_user_rrp_challenge(conn, device_id)
    end
  end

  operation(:logout,
    summary: "Logout current session",
    request_body: {"Logout params", "application/json", Schemas.LogoutRequest},
    responses: [
      ok: {"Logout result", "application/json", Schemas.OkResponse}
    ]
  )

  def logout(conn, params) do
    session = conn.assigns.current_session

    case conn.assigns[:session_kind] do
      :share_participant ->
        AuthDBSC.delete_binding("share_participant", session.id)
        Sharing.delete_participant_session(session.id)
        RefMDWeb.Endpoint.broadcast("share_socket:#{session.principal_id}", "disconnect", %{})

        if is_binary(session.device_id) do
          Phoenix.PubSub.broadcast(
            RefMD.PubSub,
            "share_device_revocation:#{session.device_id}",
            {:device_revoked, session.device_id}
          )
        end

        conn
        |> delete_share_session_cookie()
        |> delete_mount_session_cookie()
        |> json(%{ok: true})

      _ ->
        AuthDBSC.delete_binding("user", session.id)
        Auth.delete_session(session.id)
        RefMDWeb.Endpoint.broadcast("user_socket:#{session.user_id}", "disconnect", %{})

        conn
        |> delete_session_cookie()
        |> maybe_delete_mount_session_cookie(params)
        |> json(%{ok: true})
    end
  end

  defp maybe_delete_mount_session_cookie(conn, %{"clear_mount_session" => true}),
    do: delete_mount_session_cookie(conn)

  defp maybe_delete_mount_session_cookie(conn, _params), do: conn

  operation(:get_recovery,
    summary: "Get recovery data (encrypted UMK, identity keys)",
    responses: [
      ok: {"Recovery data", "application/json", Schemas.RecoveryDataResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_recovery(conn, _params) do
    user_id = conn.assigns.current_user_id
    master_key = Encryption.get_user_encrypted_master_key(user_id)

    if master_key == nil or master_key.recovery_encrypted_umk == nil or
         master_key.recovery_nonce == nil do
      conn
      |> put_status(:not_found)
      |> json(%{error: "recovery_not_configured"})
    else
      json(conn, recovery_data_response(user_id, master_key))
    end
  end

  operation(:recovery_challenge,
    summary: "Request a recovery challenge",
    request_body:
      {"Recovery challenge request", "application/json", Schemas.RecoveryChallengeRequest},
    responses: [
      ok: {"Challenge response", "application/json", Schemas.RecoveryChallengeResponse}
    ]
  )

  def recovery_challenge(conn, %{"email" => email}) do
    case Users.get_user_by_email(email) do
      nil ->
        # Anti-enumeration: return a dummy challenge
        dummy = :crypto.strong_rand_bytes(32)
        json(conn, %{challenge: Base.url_encode64(dummy, padding: false)})

      user ->
        case Auth.create_recovery_challenge(user.id) do
          {:ok, challenge} ->
            json(conn, %{challenge: Base.url_encode64(challenge, padding: false)})

          {:error, _} ->
            # Return dummy on failure too
            dummy = :crypto.strong_rand_bytes(32)
            json(conn, %{challenge: Base.url_encode64(dummy, padding: false)})
        end
    end
  end

  operation(:recovery_session,
    summary: "Establish a recovery session via Identity signature",
    request_body:
      {"Recovery session request", "application/json", Schemas.RecoverySessionRequest},
    responses: [
      ok: {"Recovery session", "application/json", Schemas.RecoverySessionResponse},
      unauthorized: {"Invalid recovery", "application/json", Schemas.ErrorResponse}
    ]
  )

  def recovery_session(conn, params) do
    email = params["email"]

    with {:ok, challenge} <- decode_binary(params["challenge"]),
         signature when is_map(signature) <- params["recovery_session_signature"],
         recovery_session_id when is_binary(recovery_session_id) <- params["recovery_session_id"],
         recovery_authorization_key_id when is_binary(recovery_authorization_key_id) <-
           params["recovery_authorization_key_id"],
         recovery_authorization_proof when is_map(recovery_authorization_proof) <-
           params["recovery_authorization_proof"],
         %{} = user <- Users.get_user_by_email(email),
         target_registration when is_map(target_registration) <-
           params["target_device_registration"],
         material <- DeviceRegistrationPayload.decode_request_material!(target_registration),
         :ok <- Devices.validate_device_registration(user.id, material) do
      registration_attrs =
        recovery_device_registration_attrs(
          conn,
          user.id,
          target_registration,
          material,
          challenge
        )

      proof =
        recovery_session_proof(
          params,
          recovery_session_id,
          recovery_authorization_key_id,
          recovery_authorization_proof
        )

      session_attrs = %{
        ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
        user_agent: get_req_header(conn, "user-agent") |> List.first()
      }

      case Auth.establish_recovery_session(
             user.id,
             challenge,
             signature,
             proof,
             registration_attrs,
             session_attrs
           ) do
        {:ok, %{context: recovery_context, session: session, token: token}} ->
          recovery_registration =
            Devices.get_valid_device_registration(recovery_context.device_registration_id)

          Security.record_device_registration_created(user.id, recovery_registration)

          conn
          |> set_session_cookie(token, false)
          |> put_registration_header(:user, session)
          |> json(%{
            user: %{
              id: user.id,
              email: user.email,
              name: user.name
            },
            session_id: session.id,
            is_recovery: true,
            audit_checkpoint: Security.current_signed_audit_checkpoint!("user", user.id)
          })

        {:error, _reason} ->
          conn
          |> put_status(:unauthorized)
          |> json(%{error: "invalid_or_expired_recovery_request"})
      end
    else
      _ ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_or_expired_recovery_request"})
    end
  end

  defp recovery_device_registration_attrs(conn, user_id, params, material, challenge) do
    %{
      user_id: user_id,
      id: material.device_id,
      name: params["name"] || "Recovered device",
      device_type: params["device_type"] || "browser",
      hybrid_encryption_public_key_material: material.hybrid_encryption_public_key_material,
      hybrid_signing_public_key_material: material.hybrid_signing_public_key_material,
      client_nonce: material.client_nonce,
      pending_registration_challenge_hash: Hash.blake3_base64url(challenge),
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip))
    }
  end

  defp recovery_session_proof(
         params,
         recovery_session_id,
         recovery_authorization_key_id,
         recovery_authorization_proof
       ) do
    %{
      recovery_authorization_key_id: recovery_authorization_key_id,
      recovery_authorization_proof: recovery_authorization_proof,
      recovery_session_id: recovery_session_id,
      recovery_capability_hash: params["recovery_capability_hash"],
      recovery_session_transcript_hash: params["recovery_session_transcript_hash"],
      pending_registration_id: params["pending_registration_id"],
      recipient_device_id: params["recipient_device_id"],
      pending_registration_binding_hash: params["pending_registration_binding_hash"],
      target_key_checkpoint_sequence: params["target_key_checkpoint_sequence"],
      target_key_checkpoint_hash: params["target_key_checkpoint_hash"],
      candidate_user_checkpoint_sequence: params["candidate_user_checkpoint_sequence"],
      candidate_user_checkpoint_hash: params["candidate_user_checkpoint_hash"],
      candidate_user_event_head_sequence: params["candidate_user_event_head_sequence"],
      candidate_user_event_head_hash: params["candidate_user_event_head_hash"],
      candidate_user_checkpoint: params["candidate_user_checkpoint"],
      candidate_user_event_ancestry: params["candidate_user_event_ancestry"],
      candidate_user_audit_sequence: params["candidate_user_audit_sequence"],
      candidate_user_audit_hash: params["candidate_user_audit_hash"]
    }
  end

  # ── Helpers ────────────────────────────────────

  defp oauth_callback_session_context(conn) do
    conn = fetch_cookies(conn)
    cookie_name = SessionCookies.session_cookie_name("user")

    with token when is_binary(token) <- Map.get(conn.cookies, cookie_name),
         {:ok, session} <- Auth.get_valid_session_by_token_base64(token),
         :ok <- require_oauth_callback_dbsc_bound_cookie(session, token) do
      %{user_id: session.user_id, session_id: session.id}
    else
      _ -> nil
    end
  end

  defp require_oauth_callback_dbsc_bound_cookie(session, token) do
    case AuthDBSC.bound_cookie_status("user", session.id, token) do
      :not_registered -> :ok
      {:ok, _binding} -> :ok
      {:error, _binding} -> {:error, :dbsc_required}
    end
  end

  defp external_account_response(account) do
    %{
      provider: account.provider,
      email: account.email,
      created_at: DateTime.to_iso8601(account.created_at)
    }
  end

  defp handle_successful_login(conn, user, params) do
    device_id = params["device_id"]
    remember_me = params["remember_me"] || false
    device_login_status = device_login_status(user.id, device_id)
    device_verified = device_login_status == :verified
    identity_recovery_required = device_login_status == :identity_recovery_required

    {:ok, session, token} =
      Auth.create_session(user.id, %{
        device_id: if(device_verified, do: device_id),
        identity_recovery_required: identity_recovery_required,
        remember_me: remember_me,
        ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
        user_agent: get_req_header(conn, "user-agent") |> List.first()
      })

    response =
      build_login_response(
        user,
        session,
        device_id,
        device_verified,
        identity_recovery_required
      )

    conn
    |> set_session_cookie(token, remember_me)
    |> put_registration_header(:user, session)
    |> json(response)
  end

  defp handle_dbsc_register(conn, session_kind) do
    session = conn.assigns.current_session
    proof = get_req_header(conn, "secure-session-response") |> List.first()

    case AuthDBSC.register_session(session_kind, session, proof) do
      {:ok, binding, token} ->
        conn
        |> put_dbsc_hardening_headers()
        |> put_dbsc_cookie(session_kind, token)
        |> put_challenge_header(binding)
        |> json(dbsc_session_instructions(conn, binding, session_kind))

      {:error, _reason} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_dbsc_proof"})
    end
  end

  defp handle_dbsc_mount_register(conn) do
    proof = get_req_header(conn, "secure-session-response") |> List.first()

    with {:ok, mount_session} <- current_mount_password_session(conn),
         {:ok, binding, token} <-
           AuthDBSC.register_session("mount", mount_session, proof, &mount_dbsc_token/1) do
      conn
      |> put_dbsc_hardening_headers()
      |> put_bound_session_cookie("mount", token)
      |> put_challenge_header(binding)
      |> json(dbsc_session_instructions(conn, binding, "mount"))
    else
      _ ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_dbsc_proof"})
    end
  end

  defp handle_dbsc_refresh(conn, session_kind) do
    handle_dbsc_refresh(conn, session_kind, nil)
  end

  defp handle_dbsc_refresh(conn, session_kind, token_issuer) do
    session_identifier = get_req_header(conn, "sec-secure-session-id") |> List.first()
    proof = get_req_header(conn, "secure-session-response") |> List.first()

    refresh_result =
      if is_function(token_issuer, 1) do
        AuthDBSC.refresh_session_by_identifier(
          session_kind,
          unwrap_structured_header_string(session_identifier),
          proof,
          token_issuer
        )
      else
        AuthDBSC.refresh_session_by_identifier(
          session_kind,
          unwrap_structured_header_string(session_identifier),
          proof
        )
      end

    case refresh_result do
      {:ok, binding, token} ->
        conn
        |> put_dbsc_hardening_headers()
        |> put_bound_session_cookie(session_kind, token)
        |> put_challenge_header(binding)
        |> json(dbsc_session_instructions(conn, binding, session_kind))

      {:error, _reason} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_dbsc_proof"})
    end
  end

  defp put_dbsc_cookie(conn, session_kind, token),
    do: put_bound_session_cookie(conn, session_kind, token)

  defp put_bound_session_cookie(conn, session_kind, token),
    do: set_bound_session_cookie(conn, session_kind, token)

  defp dbsc_session_instructions(conn, binding, session_kind) do
    AuthDBSC.session_instructions(binding, origin(conn), dbsc_credential_name(session_kind))
  end

  defp dbsc_credential_name(session_kind), do: session_cookie_name(session_kind)

  defp current_mount_password_session(conn) do
    with token when is_binary(token) <- request_cookie(conn, "__Host-refmd-mount-session"),
         {:ok, signed_token} <- Base.url_decode64(token, padding: false),
         {:ok, %{"mount_id" => mount_id, "share_id" => share_id, "user_id" => user_id}} <-
           Phoenix.Token.verify(RefMDWeb.Endpoint, "mount_password_session", signed_token,
             max_age: 24 * 60 * 60
           ),
         true <- is_binary(mount_id) and is_binary(share_id) and is_binary(user_id) do
      {:ok,
       %{
         id: mount_id,
         share_id: share_id,
         user_id: user_id,
         expires_at: DateTime.add(DateTime.utc_now(), 24 * 60 * 60, :second)
       }}
    else
      _ -> {:error, :invalid_mount_session}
    end
  end

  defp mount_dbsc_token(%{session_id: mount_id}) when is_binary(mount_id) do
    case RefMD.Repo.get(RefMD.Sharing.ShareMount, mount_id) do
      %RefMD.Sharing.ShareMount{} = mount ->
        {:ok, mount_password_session_token(mount.id, mount.share_id, mount.user_id)}

      _ ->
        {:error, :invalid_dbsc_session}
    end
  end

  defp mount_dbsc_token(_binding), do: {:error, :invalid_dbsc_session}

  defp mount_password_session_token(mount_id, share_id, user_id) do
    Phoenix.Token.sign(
      RefMDWeb.Endpoint,
      "mount_password_session",
      %{"mount_id" => mount_id, "share_id" => share_id, "user_id" => user_id}
    )
  end

  defp request_cookie(conn, name) do
    conn
    |> get_req_header("cookie")
    |> List.first("")
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.trim(part) |> String.split("=", parts: 2) do
        [^name, value] -> value
        _ -> nil
      end
    end)
  end

  defp put_dbsc_hardening_headers(conn) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("cross-origin-resource-policy", "same-origin")
    |> put_resp_header("x-frame-options", "DENY")
  end

  defp unwrap_structured_header_string(nil), do: nil

  defp unwrap_structured_header_string(value) when is_binary(value) do
    value = String.trim(value)

    if String.starts_with?(value, "\"") and String.ends_with?(value, "\"") and
         String.length(value) >= 2 do
      value
      |> String.slice(1, String.length(value) - 2)
      |> String.replace(~s(\\"), ~s("))
      |> String.replace(~s(\\\\), ~s(\\))
    else
      value
    end
  end

  defp device_login_status(_user_id, nil), do: :device_registration_required

  defp device_login_status(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil, identity_wipe_required_at: nil} ->
        :verified

      %{user_id: ^user_id, revoked_at: nil, identity_wipe_required_at: wipe_required_at}
      when not is_nil(wipe_required_at) ->
        :identity_recovery_required

      %{user_id: ^user_id, identity_replaced_by_device_id: replacement_device_id}
      when not is_nil(replacement_device_id) ->
        :identity_recovery_required

      _ ->
        :device_registration_required
    end
  end

  defp oauth_redirect_uri(conn, provider) do
    configured_redirect_uri = oauth_configured_redirect_uri(provider)

    if is_binary(configured_redirect_uri) and String.trim(configured_redirect_uri) != "" do
      configured_redirect_uri
    else
      request_oauth_redirect_uri(conn, provider)
    end
  end

  defp request_oauth_redirect_uri(conn, provider) do
    port =
      case {conn.scheme, conn.port} do
        {:http, 80} -> ""
        {:https, 443} -> ""
        {_scheme, port} -> ":#{port}"
      end

    "#{conn.scheme}://#{conn.host}#{port}/api/auth/oauth/#{provider}/callback"
  end

  defp oauth_configured_redirect_uri("google") do
    :refmd |> Application.get_env(:oauth, []) |> get_in([:google, :redirect_uri])
  end

  defp oauth_configured_redirect_uri("github") do
    :refmd |> Application.get_env(:oauth, []) |> get_in([:github, :redirect_uri])
  end

  defp oauth_configured_redirect_uri(_provider), do: nil

  defp safe_return_to(path) when is_binary(path) do
    uri = URI.parse(path)

    cond do
      uri.scheme != nil -> "/"
      uri.host != nil -> "/"
      not String.starts_with?(path, "/") -> "/"
      String.starts_with?(path, "//") -> "/"
      true -> path
    end
  end

  defp safe_return_to(_), do: "/"

  defp oauth_error_payload(reason) do
    payload = %{error: oauth_error(reason)}

    case oauth_error_details(reason) do
      nil -> payload
      details -> Map.put(payload, :details, details)
    end
  end

  defp oauth_error({reason, _details}), do: oauth_error(reason)
  defp oauth_error(:invalid_provider), do: "invalid_oauth_provider"
  defp oauth_error(:oauth_provider_disabled), do: "oauth_provider_disabled"
  defp oauth_error(:oauth_provider_not_configured), do: "oauth_provider_not_configured"
  defp oauth_error(:invalid_oauth_state), do: "invalid_oauth_state"
  defp oauth_error(:oauth_token_exchange_failed), do: "oauth_token_exchange_failed"
  defp oauth_error(:oauth_userinfo_failed), do: "oauth_userinfo_failed"
  defp oauth_error(:oauth_email_unverified), do: "oauth_email_unverified"
  defp oauth_error(:oauth_provider_unavailable), do: "oauth_provider_unavailable"
  defp oauth_error(:oauth_account_link_required), do: "oauth_account_link_required"
  defp oauth_error(:oauth_external_account_conflict), do: "oauth_external_account_conflict"
  defp oauth_error(_), do: "oauth_failed"

  defp oauth_error_details({_reason, details}) when is_map(details) do
    if Application.get_env(:refmd, :oauth_error_details, false), do: details
  end

  defp oauth_error_details(_reason), do: nil

  defp build_login_response(
         user,
         session,
         device_id,
         device_verified,
         identity_recovery_required
       ) do
    master_key = Encryption.get_user_encrypted_master_key(user.id)

    keys =
      if device_verified do
        Encryption.get_login_keys(user.id, device_id)
        |> format_login_keys()
      end

    kdf_migration_required =
      master_key != nil and master_key.kdf_params != nil and
        master_key.kdf_params != @target_kdf_params

    response = %{
      user: %{
        id: user.id,
        email: user.email,
        name: user.name
      },
      session_id: session.id,
      device_verified: device_verified,
      identity_recovery_required: identity_recovery_required
    }

    response = if keys, do: Map.put(response, :keys, keys), else: response

    if kdf_migration_required do
      Map.merge(response, %{
        kdf_migration_required: true,
        target_kdf_params: @target_kdf_params
      })
    else
      response
    end
  end

  defp format_login_keys(keys) do
    mk = keys.encrypted_master_key
    ik = keys.encrypted_identity_key

    result = %{
      encrypted_identity_hybrid_encryption_private_key_material:
        encode_struct_binary(ik, :encrypted_identity_hybrid_encryption_private_key_material),
      identity_hybrid_encryption_private_key_material_nonce:
        encode_struct_binary(ik, :identity_hybrid_encryption_private_key_material_nonce),
      identity_encryption_key_id: struct_field(ik, :encryption_key_id),
      encrypted_identity_hybrid_signing_private_key_material:
        encode_struct_binary(ik, :encrypted_identity_hybrid_signing_private_key_material),
      identity_hybrid_signing_private_key_material_nonce:
        encode_struct_binary(ik, :identity_hybrid_signing_private_key_material_nonce),
      identity_signing_key_id: struct_field(ik, :signing_key_id),
      identity_key_epoch: struct_field(ik, :identity_key_epoch),
      identity_rotation_due_at: struct_field(keys.identity_public_key, :rotation_due_at),
      identity_key_checkpoint: key_directory_envelope(keys.identity_key_checkpoint)
    }

    if mk && mk.auth_type == "password" do
      Map.merge(result, %{
        encrypted_umk: encode_binary(mk.encrypted_umk),
        umk_nonce: encode_binary(mk.umk_nonce)
      })
    else
      result
    end
  end

  defp key_directory_envelope(nil), do: nil

  defp key_directory_envelope(checkpoint) do
    %{payload: checkpoint.payload, signatures: checkpoint.signatures}
  end

  defp recovery_data_response(user_id, master_key) do
    identity_key = Encryption.get_user_encrypted_identity_key(user_id)
    identity_public_key = Encryption.get_user_identity_public_key(user_id)
    user_pin = Encryption.current_user_key_directory_pin(user_id)
    user_checkpoint = Encryption.current_user_key_directory_checkpoint(user_id)

    %{
      recovery_encrypted_umk: encode_binary(master_key.recovery_encrypted_umk),
      recovery_nonce: encode_binary(master_key.recovery_nonce),
      encrypted_identity_hybrid_encryption_private_key_material:
        encode_struct_binary(
          identity_key,
          :encrypted_identity_hybrid_encryption_private_key_material
        ),
      identity_hybrid_encryption_private_key_material_nonce:
        encode_struct_binary(
          identity_key,
          :identity_hybrid_encryption_private_key_material_nonce
        ),
      identity_encryption_key_id: struct_field(identity_key, :encryption_key_id),
      encrypted_identity_hybrid_signing_private_key_material:
        encode_struct_binary(
          identity_key,
          :encrypted_identity_hybrid_signing_private_key_material
        ),
      identity_hybrid_signing_private_key_material_nonce:
        encode_struct_binary(identity_key, :identity_hybrid_signing_private_key_material_nonce),
      identity_signing_key_id: struct_field(identity_key, :signing_key_id),
      identity_key_epoch: struct_field(identity_key, :identity_key_epoch),
      identity_rotation_due_at: struct_field(identity_public_key, :rotation_due_at),
      hybrid_encryption_public_key_material:
        struct_field(identity_public_key, :hybrid_encryption_public_key_material),
      hybrid_signing_public_key_material:
        struct_field(identity_public_key, :hybrid_signing_public_key_material),
      candidate_user_checkpoint_sequence: user_pin && user_pin.checkpoint_sequence,
      candidate_user_checkpoint_hash: user_pin && user_pin.checkpoint_hash,
      candidate_user_event_head_sequence: user_pin && user_pin.event_head_sequence,
      candidate_user_event_head_hash: user_pin && user_pin.event_head_hash,
      candidate_user_checkpoint:
        user_checkpoint &&
          %{
            payload: user_checkpoint.payload,
            signatures: user_checkpoint.signatures
          },
      candidate_user_checkpoint_ancestry:
        Auth.user_key_directory_checkpoint_ancestry(user_id, user_pin),
      candidate_user_event_ancestry: Auth.user_key_directory_event_ancestry(user_id, user_pin),
      candidate_user_rotation_deletion_evidences:
        Auth.user_identity_rotation_deletion_evidences(user_id, user_pin),
      candidate_user_audit_checkpoint: Security.current_signed_audit_checkpoint!("user", user_id),
      candidate_workspace_checkpoints: candidate_workspace_checkpoints(user_id)
    }
  end

  defp candidate_workspace_checkpoints(user_id) do
    user_id
    |> RefMD.Workspaces.get_user_workspace_ids()
    |> Enum.map(fn workspace_id ->
      case {
        Encryption.current_workspace_key_directory_pin(workspace_id),
        Encryption.current_workspace_key_directory_checkpoint(workspace_id)
      } do
        {nil, _} ->
          nil

        {_, nil} ->
          nil

        {pin, checkpoint} ->
          %{
            workspace_id: workspace_id,
            checkpoint: %{
              payload: checkpoint.payload,
              signatures: checkpoint.signatures
            },
            checkpoint_ancestry: workspace_key_directory_checkpoint_ancestry(workspace_id, pin),
            event_ancestry: workspace_key_directory_event_ancestry(workspace_id, pin)
          }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp workspace_key_directory_checkpoint_ancestry(_workspace_id, %{checkpoint_sequence: sequence})
       when sequence <= 1,
       do: []

  defp workspace_key_directory_checkpoint_ancestry(workspace_id, pin) do
    Encryption.workspace_key_directory_checkpoints_between(
      workspace_id,
      1,
      pin.checkpoint_sequence - 1
    )
    |> Enum.map(&%{payload: &1.payload, signatures: &1.signatures})
  end

  defp workspace_key_directory_event_ancestry(workspace_id, pin) do
    Encryption.workspace_key_directory_events_after_until(
      workspace_id,
      0,
      pin.event_head_sequence
    )
    |> Enum.map(&%{payload: &1.payload, signatures: &1.signatures})
  end

  defp struct_field(nil, _field), do: nil
  defp struct_field(struct, field), do: Map.get(struct, field)

  defp encode_struct_binary(nil, _field), do: nil
  defp encode_struct_binary(struct, field), do: encode_binary(Map.get(struct, field))

  defp create_user_rrp_challenge(conn, nil),
    do: conn |> put_status(:forbidden) |> json(%{error: "missing_device_id"})

  defp create_user_rrp_challenge(conn, device_id) do
    user_id = conn.assigns.current_user_id

    with {:ok, device} <- get_user_rrp_device(user_id, device_id),
         {:ok, challenge} <-
           Auth.create_rrp_challenge(user_id, device_id, conn.assigns.current_session.id) do
      user_rrp_challenge_response(conn, device, user_id, challenge)
    else
      {:error, :invalid_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      {:error, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "challenge_creation_failed"})
    end
  end

  defp create_share_rrp_challenge(conn, nil),
    do: conn |> put_status(:forbidden) |> json(%{error: "missing_device_id"})

  defp create_share_rrp_challenge(conn, device_id) do
    principal_id = conn.assigns.share_participant_principal_id
    share_id = conn.assigns.current_share_id

    with :ok <- verify_share_rrp_session_device(conn.assigns.current_session.device_id, device_id),
         {:ok, device} <- get_share_rrp_device(share_id, principal_id, device_id),
         {:ok, challenge} <-
           Sharing.create_rrp_challenge(
             share_id,
             principal_id,
             device_id,
             conn.assigns.current_session.id
           ) do
      share_rrp_challenge_response(conn, device, share_id, challenge)
    else
      {:error, :device_session_mismatch} ->
        conn |> put_status(:forbidden) |> json(%{error: "device_session_mismatch"})

      {:error, :invalid_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      {:error, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "challenge_creation_failed"})
    end
  end

  defp get_user_rrp_device(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil, identity_wipe_required_at: nil} = device ->
        {:ok, device}

      _ ->
        {:error, :invalid_device}
    end
  end

  defp get_share_rrp_device(share_id, principal_id, device_id) do
    case Sharing.get_participant_device(share_id, principal_id, device_id) do
      %{principal_id: ^principal_id} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_share_rrp_session_device(device_id, device_id) when is_binary(device_id), do: :ok
  defp verify_share_rrp_session_device(_, _), do: {:error, :device_session_mismatch}

  defp user_rrp_challenge_response(conn, device, user_id, challenge) do
    json(conn, %{
      actor: RrpTranscript.user_actor!(device, user_id),
      challenge: Base.url_encode64(challenge, padding: false),
      session: RrpSessionBinding.for_user_session(conn.assigns.current_session)
    })
  end

  defp share_rrp_challenge_response(conn, device, share_id, challenge) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    json(conn, %{
      actor: RrpTranscript.share_participant_actor!(device, share_id, workspace_id),
      challenge: Base.url_encode64(challenge, padding: false),
      session: RrpSessionBinding.for_share_session(conn.assigns.current_session)
    })
  end
end
