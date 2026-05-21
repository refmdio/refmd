defmodule RefMDWeb.AuthController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Auth, Devices, Encryption, Sharing, Users, Workspaces}
  alias RefMD.Crypto
  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, Signature}
  alias RefMDWeb.Http.PopSessionBinding
  alias RefMDWeb.Http.PopTranscript

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

  @spec salt(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec register(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def register(conn, %{"user_id" => user_id} = params) when is_binary(user_id) do
    with {:ok, hybrid_encryption_public_key_material} <-
           validate_identity_encryption_public_key_material(
             params["hybrid_encryption_public_key_material"],
             user_id
           ),
         {:ok, x25519_public_key} <-
           identity_encryption_x25519_public_key(hybrid_encryption_public_key_material),
         {:ok, hybrid_signing_public_key_material} <-
           validate_identity_public_key_material(
             params["hybrid_signing_public_key_material"],
             user_id
           ) do
      cond do
        not valid_uuid?(user_id) ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_user_id_format"})

        byte_size(x25519_public_key) != 32 ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "invalid_hybrid_encryption_public_key_material"})

        not Crypto.valid_x25519_public_key?(x25519_public_key) ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "invalid_hybrid_encryption_public_key_material"})

        params["kdf_params"] != @target_kdf_params ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_kdf_params"})

        true ->
          register_with_validated_keys(
            conn,
            params,
            user_id,
            hybrid_encryption_public_key_material,
            hybrid_signing_public_key_material
          )
      end
    else
      :error ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_required_key"})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  def register(conn, _params) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "user_id_required"})
  end

  defp register_with_validated_keys(
         conn,
         params,
         user_id,
         hybrid_encryption_public_key_material,
         hybrid_signing_public_key_material
       ) do
    do_register(
      conn,
      params,
      user_id,
      hybrid_encryption_public_key_material,
      hybrid_signing_public_key_material
    )
  end

  defp do_register(
         conn,
         params,
         user_id,
         hybrid_encryption_public_key_material,
         hybrid_signing_public_key_material
       ) do
    RefMD.Repo.transaction(fn ->
      user_attrs = %{email: String.downcase(params["email"]), name: params["name"]}
      user_struct = %RefMD.Users.User{id: user_id}

      with {:ok, user} <- Users.create_user_with_struct(user_struct, user_attrs),
           {:ok, _settings} <- Users.create_user_settings(user.id),
           {:ok, _master_key} <-
             Encryption.create_user_encrypted_master_key(%{
               user_id: user.id,
               auth_type: "password",
               encrypted_umk: decode_optional_binary(params["encrypted_umk"]),
               umk_nonce: decode_optional_binary(params["umk_nonce"]),
               salt: decode_optional_binary(params["salt"]),
               kdf_type: "argon2id",
               kdf_params: params["kdf_params"],
               auth_key_hash: Bcrypt.hash_pwd_salt(params["auth_key"]),
               recovery_encrypted_umk: decode_optional_binary(params["recovery_encrypted_umk"]),
               recovery_nonce: decode_optional_binary(params["recovery_nonce"]),
               recovery_authorization_public_material:
                 params["recovery_authorization_public_material"],
               recovery_authorization_key_id: params["recovery_authorization_key_id"]
             }),
           {:ok, identity_pub} <-
             Encryption.create_user_identity_public_key(%{
               user_id: user.id,
               hybrid_encryption_public_key_material: hybrid_encryption_public_key_material,
               hybrid_signing_public_key_material: hybrid_signing_public_key_material,
               pending_registration_challenge_hash: unissued_registration_challenge_hash()
             }),
           {:ok, _identity_key} <-
             Encryption.create_user_encrypted_identity_key(%{
               user_id: user.id,
               encrypted_identity_hybrid_encryption_private_key_material:
                 decode_optional_binary(
                   params["encrypted_identity_hybrid_encryption_private_key_material"]
                 ),
               identity_hybrid_encryption_private_key_material_nonce:
                 decode_optional_binary(
                   params["identity_hybrid_encryption_private_key_material_nonce"]
                 ),
               encryption_key_id: identity_pub.encryption_key_id,
               encrypted_identity_hybrid_signing_private_key_material:
                 decode_optional_binary(
                   params["encrypted_identity_hybrid_signing_private_key_material"]
                 ),
               identity_hybrid_signing_private_key_material_nonce:
                 decode_optional_binary(
                   params["identity_hybrid_signing_private_key_material_nonce"]
                 ),
               signing_key_id: identity_pub.signing_key_id
             }),
           {:ok, workspace} <-
             Workspaces.create_default_workspace(
               user.id,
               "#{params["name"] || "My"}'s Workspace"
             ),
           {_, owner_role} <- Workspaces.get_member_with_role(workspace.id, user.id),
           {:ok, session, token} <-
             Auth.create_session(user.id, %{
               remember_me: false,
               ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
               user_agent: get_req_header(conn, "user-agent") |> List.first()
             }) do
        %{
          user: user,
          workspace: workspace,
          owner_role: owner_role,
          session: session,
          token: token
        }
      else
        {:error, reason} -> RefMD.Repo.rollback(reason)
        nil -> RefMD.Repo.rollback(:workspace_owner_role_missing)
      end
    end)
    |> case do
      {:ok,
       %{
         user: user,
         workspace: workspace,
         owner_role: owner_role,
         session: session,
         token: token
       }} ->
        conn
        |> set_session_cookie(token, session.remember_me)
        |> put_status(:created)
        |> json(%{
          user: %{
            id: user.id,
            email: user.email,
            name: user.name
          },
          workspace_id: workspace.id,
          workspace_owner_role_id: owner_role.id,
          session_id: session.id
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "registration_failed",
          details: format_errors(reason)
        })
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  defp unissued_registration_challenge_hash do
    32
    |> :crypto.strong_rand_bytes()
    |> Hash.blake3_base64url()
  end

  operation(:login,
    summary: "Login with credentials",
    request_body: {"Login params", "application/json", Schemas.LoginRequest},
    responses: [
      ok: {"Login response", "application/json", Schemas.LoginResponse},
      unauthorized: {"Invalid credentials", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec login(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  operation(:me,
    summary: "Get current session info",
    responses: [
      ok: {"Session info", "application/json", Schemas.MeResponse},
      unauthorized: {"Not authenticated", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec me(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  operation(:key_restore,
    summary: "Get current device key restore payload",
    responses: [
      ok: {"Key restore payload", "application/json", Schemas.LoginKeys},
      unauthorized: {"Not authenticated", "application/json", Schemas.ErrorResponse},
      forbidden: {"Device is not verified", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec key_restore(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec kdf_migration(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec verify_key(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  operation(:pop_challenge,
    summary: "Request a PoP challenge nonce",
    parameters: [
      x_pop_device_id: [
        in: :header,
        name: :"x-pop-device-id",
        description: "PoP signing device id.",
        required: true,
        schema: %OpenApiSpex.Schema{type: :string, format: :uuid}
      ]
    ],
    responses: [
      ok: {"Challenge response", "application/json", Schemas.PopChallengeResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec pop_challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  operation(:ws_token,
    summary: "Generate a short-lived WebSocket authentication token",
    responses: [
      ok: {"WS token", "application/json", Schemas.WsTokenResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec ws_token(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def ws_token(conn, _params) do
    session = conn.assigns.current_session

    token =
      case conn.assigns[:session_kind] do
        :share_participant -> Sharing.generate_ws_token(session.id)
        _ -> Auth.generate_ws_token(session.id)
      end

    json(conn, %{token: token})
  end

  @spec pop_challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def pop_challenge(conn, _params) do
    device_id = get_req_header(conn, "x-pop-device-id") |> List.first()

    case conn.assigns[:session_kind] do
      :share_participant -> create_share_pop_challenge(conn, device_id)
      _ -> create_user_pop_challenge(conn, device_id)
    end
  end

  operation(:logout,
    summary: "Logout current session",
    request_body: {"Logout params", "application/json", Schemas.LogoutRequest},
    responses: [
      ok: {"Logout result", "application/json", Schemas.OkResponse}
    ]
  )

  @spec logout(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def logout(conn, params) do
    session = conn.assigns.current_session

    case conn.assigns[:session_kind] do
      :share_participant ->
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

  @spec get_recovery(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec recovery_challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec recovery_session(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def recovery_session(conn, params) do
    email = params["email"]

    with {:ok, challenge} <- decode_binary(params["challenge"]),
         signature when is_map(signature) <- params["recovery_session_signature"],
         recovery_session_id when is_binary(recovery_session_id) <- params["recovery_session_id"],
         recovery_authorization_key_id when is_binary(recovery_authorization_key_id) <-
           params["recovery_authorization_key_id"],
         recovery_authorization_proof when is_map(recovery_authorization_proof) <-
           params["recovery_authorization_proof"],
         %{} = user <- Users.get_user_by_email(email) do
      case Auth.verify_recovery_session(user.id, challenge, signature, %{
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
             candidate_user_event_ancestry: params["candidate_user_event_ancestry"]
           }) do
        {:ok, recovery_context} ->
          {:ok, session, token} =
            Auth.create_session(user.id, %{
              id: recovery_context.recovery_session_id,
              is_recovery: true,
              device_registration_id: recovery_context.device_registration_id,
              recovery_session_transcript_hash: recovery_context.recovery_session_transcript_hash,
              recovery_capability_hash: recovery_context.recovery_capability_hash,
              pending_registration_binding_hash:
                recovery_context.pending_registration_binding_hash,
              target_key_checkpoint_sequence: recovery_context.target_key_checkpoint_sequence,
              target_key_checkpoint_hash: recovery_context.target_key_checkpoint_hash,
              candidate_user_checkpoint_sequence:
                recovery_context.candidate_user_checkpoint_sequence,
              candidate_user_checkpoint_hash: recovery_context.candidate_user_checkpoint_hash,
              candidate_user_event_head_sequence:
                recovery_context.candidate_user_event_head_sequence,
              candidate_user_event_head_hash: recovery_context.candidate_user_event_head_hash,
              recovered_identity_signing_key_id:
                recovery_context.recovered_identity_signing_key_id,
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: get_req_header(conn, "user-agent") |> List.first()
            })

          conn
          |> set_session_cookie(token, false)
          |> json(%{
            user: %{
              id: user.id,
              email: user.email,
              name: user.name
            },
            session_id: session.id,
            is_recovery: true
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

  # ── Helpers ────────────────────────────────────

  defp handle_successful_login(conn, user, params) do
    device_id = params["device_id"]
    remember_me = params["remember_me"] || false
    device_verified = check_device_verified(user.id, device_id)

    {:ok, session, token} =
      Auth.create_session(user.id, %{
        device_id: if(device_verified, do: device_id),
        remember_me: remember_me,
        ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
        user_agent: get_req_header(conn, "user-agent") |> List.first()
      })

    response =
      build_login_response(user, session, device_id, device_verified)

    conn
    |> set_session_cookie(token, remember_me)
    |> json(response)
  end

  defp check_device_verified(_user_id, nil), do: false

  defp check_device_verified(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} -> true
      _ -> false
    end
  end

  defp build_login_response(user, session, device_id, device_verified) do
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
      device_verified: device_verified
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

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/

  defp valid_uuid?(str) when is_binary(str), do: Regex.match?(@uuid_regex, str)

  defp validate_identity_public_key_material(material, user_id) when is_map(material) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == "identity",
         true <- material["owner_id"] == user_id do
      {:ok, material}
    else
      _ -> :error
    end
  rescue
    ArgumentError -> :error
  end

  defp validate_identity_public_key_material(_, _), do: :error

  defp validate_identity_encryption_public_key_material(
         material,
         user_id
       )
       when is_map(material) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         true <- material["owner_kind"] == "identity",
         true <- material["owner_id"] == user_id do
      {:ok, material}
    else
      _ -> :error
    end
  rescue
    ArgumentError -> :error
  end

  defp validate_identity_encryption_public_key_material(_, _), do: :error

  defp identity_encryption_x25519_public_key(material) do
    {:ok, HybridEncryptionMaterial.x25519_public!(material)}
  rescue
    ArgumentError -> :error
  end

  defp format_login_keys(keys) do
    mk = keys.encrypted_master_key
    ik = keys.encrypted_identity_key

    result = %{
      encrypted_identity_hybrid_encryption_private_key_material:
        encode_binary(ik && ik.encrypted_identity_hybrid_encryption_private_key_material),
      identity_hybrid_encryption_private_key_material_nonce:
        encode_binary(ik && ik.identity_hybrid_encryption_private_key_material_nonce),
      identity_encryption_key_id: ik && ik.encryption_key_id,
      encrypted_identity_hybrid_signing_private_key_material:
        encode_binary(ik && ik.encrypted_identity_hybrid_signing_private_key_material),
      identity_hybrid_signing_private_key_material_nonce:
        encode_binary(ik && ik.identity_hybrid_signing_private_key_material_nonce),
      identity_signing_key_id: ik && ik.signing_key_id
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
      candidate_user_event_ancestry: Auth.user_key_directory_event_ancestry(user_id, user_pin),
      candidate_workspace_checkpoints: candidate_workspace_checkpoints(user_id)
    }
  end

  defp candidate_workspace_checkpoints(user_id) do
    user_id
    |> RefMD.Workspaces.get_user_workspace_ids()
    |> Enum.map(fn workspace_id ->
      case Encryption.current_workspace_key_directory_checkpoint(workspace_id) do
        nil ->
          nil

        checkpoint ->
          %{
            workspace_id: workspace_id,
            checkpoint: %{
              payload: checkpoint.payload,
              signatures: checkpoint.signatures
            }
          }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp struct_field(nil, _field), do: nil
  defp struct_field(struct, field), do: Map.get(struct, field)

  defp encode_struct_binary(nil, _field), do: nil
  defp encode_struct_binary(struct, field), do: encode_binary(Map.get(struct, field))

  defp create_user_pop_challenge(conn, nil),
    do: conn |> put_status(:forbidden) |> json(%{error: "missing_device_id"})

  defp create_user_pop_challenge(conn, device_id) do
    user_id = conn.assigns.current_user_id

    with {:ok, device} <- get_user_pop_device(user_id, device_id),
         {:ok, challenge} <-
           Auth.create_pop_challenge(user_id, device_id, conn.assigns.current_session.id) do
      user_pop_challenge_response(conn, device, user_id, challenge)
    else
      {:error, :invalid_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      {:error, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "challenge_creation_failed"})
    end
  end

  defp create_share_pop_challenge(conn, nil),
    do: conn |> put_status(:forbidden) |> json(%{error: "missing_device_id"})

  defp create_share_pop_challenge(conn, device_id) do
    principal_id = conn.assigns.share_participant_principal_id
    share_id = conn.assigns.current_share_id

    with :ok <- verify_share_pop_session_device(conn.assigns.current_session.device_id, device_id),
         {:ok, device} <- get_share_pop_device(share_id, principal_id, device_id),
         {:ok, challenge} <-
           Sharing.create_pop_challenge(
             share_id,
             principal_id,
             device_id,
             conn.assigns.current_session.id
           ) do
      share_pop_challenge_response(conn, device, share_id, challenge)
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

  defp get_user_pop_device(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp get_share_pop_device(share_id, principal_id, device_id) do
    case Sharing.get_participant_device(share_id, principal_id, device_id) do
      %{principal_id: ^principal_id} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_share_pop_session_device(device_id, device_id) when is_binary(device_id), do: :ok
  defp verify_share_pop_session_device(_, _), do: {:error, :device_session_mismatch}

  defp user_pop_challenge_response(conn, device, user_id, challenge) do
    json(conn, %{
      actor: PopTranscript.user_actor!(device, user_id),
      challenge: Base.url_encode64(challenge, padding: false),
      session: PopSessionBinding.for_user_session(conn.assigns.current_session)
    })
  end

  defp share_pop_challenge_response(conn, device, share_id, challenge) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    json(conn, %{
      actor: PopTranscript.share_participant_actor!(device, share_id, workspace_id),
      challenge: Base.url_encode64(challenge, padding: false),
      session: PopSessionBinding.for_share_session(conn.assigns.current_session)
    })
  end
end
