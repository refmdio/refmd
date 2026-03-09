defmodule RefMDWeb.AuthController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Accounts, Encryption, Workspaces}
  alias RefMDWeb.{Schemas, CryptoValidation}

  @target_kdf_params %{
    "algorithm" => "argon2id",
    "memory" => 65536,
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
      case Accounts.get_salt_for_email(email) do
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

  def register(conn, %{"user_id" => user_id} = params) when is_binary(user_id) do
    with {:ok, ecdh_public_key} <- decode_required(params["ecdh_public_key"]),
         {:ok, signing_public_key} <- decode_required(params["signing_public_key"]) do
      cond do
        not valid_uuid?(user_id) ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_user_id_format"})

        byte_size(ecdh_public_key) != 32 ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_ecdh_public_key_size"})

        not CryptoValidation.valid_x25519_public_key?(ecdh_public_key) ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_ecdh_public_key"})

        byte_size(signing_public_key) != 32 ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_signing_public_key_size"})

        not CryptoValidation.valid_ed25519_public_key?(signing_public_key) ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_signing_public_key"})

        params["kdf_params"] != @target_kdf_params ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_kdf_params"})

        true ->
          register_with_validated_keys(conn, params, user_id, ecdh_public_key, signing_public_key)
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

  defp register_with_validated_keys(conn, params, user_id, ecdh_public_key, signing_public_key) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:user, fn _repo, _changes ->
      user_attrs = %{email: String.downcase(params["email"]), name: params["name"]}
      user_struct = %RefMD.Accounts.User{id: user_id}
      Accounts.create_user_with_struct(user_struct, user_attrs)
    end)
    |> Ecto.Multi.run(:settings, fn _repo, %{user: user} ->
      Accounts.create_user_settings(user.id)
    end)
    |> Ecto.Multi.run(:identity_public_key, fn _repo, %{user: user} ->
      Encryption.create_user_identity_public_key(%{
        user_id: user.id,
        ecdh_public_key: ecdh_public_key,
        signing_public_key: signing_public_key
      })
    end)
    |> Ecto.Multi.run(:encrypted_master_key, fn _repo, %{user: user} ->
      Encryption.create_user_encrypted_master_key(%{
        user_id: user.id,
        auth_type: "password",
        encrypted_umk: decode_binary!(params["encrypted_umk"]),
        umk_nonce: decode_binary!(params["umk_nonce"]),
        salt: decode_binary!(params["salt"]),
        kdf_type: "argon2id",
        kdf_params: params["kdf_params"],
        auth_key_hash: Bcrypt.hash_pwd_salt(params["auth_key"]),
        recovery_encrypted_umk: decode_binary!(params["recovery_encrypted_umk"]),
        recovery_nonce: decode_binary!(params["recovery_nonce"])
      })
    end)
    |> Ecto.Multi.run(:encrypted_identity_key, fn _repo, %{user: user} ->
      Encryption.create_user_encrypted_identity_key(%{
        user_id: user.id,
        encrypted_ecdh_private: decode_binary!(params["encrypted_ecdh_private"]),
        encrypted_ecdh_private_nonce: decode_binary!(params["encrypted_ecdh_private_nonce"]),
        encrypted_signing_private: decode_binary!(params["encrypted_signing_private"]),
        encrypted_signing_private_nonce: decode_binary!(params["encrypted_signing_private_nonce"])
      })
    end)
    |> Ecto.Multi.run(:workspace, fn _repo, %{user: user} ->
      user_name = params["name"] || "My"
      Workspaces.create_default_workspace(user.id, "#{user_name}'s Workspace")
    end)
    |> Ecto.Multi.run(:session, fn _repo, %{user: user} ->
      {:ok, session, token} =
        Accounts.create_session(user.id, %{
          remember_me: false,
          ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
          user_agent: get_req_header(conn, "user-agent") |> List.first()
        })

      {:ok, {session, token}}
    end)
    |> RefMD.Repo.transaction()
    |> case do
      {:ok, %{user: user, workspace: workspace, session: {session, token}}} ->
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
          session_id: session.id
        })

      {:error, step, changeset, _changes} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "registration_failed", step: to_string(step), details: format_errors(changeset)})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:login,
    summary: "Login with credentials",
    request_body: {"Login params", "application/json", Schemas.LoginRequest},
    responses: [
      ok: {"Login response", "application/json", Schemas.LoginResponse},
      unauthorized: {"Invalid credentials", "application/json", Schemas.ErrorResponse}
    ]
  )

  def login(conn, %{"auth_key" => auth_key, "email" => email} = params) do
    case Accounts.verify_auth_key(email, auth_key) do
      {:ok, user} ->
        device_id = params["device_id"]
        remember_me = params["remember_me"] || false

        user_id = user.id

        device_verified =
          if device_id do
            case Accounts.get_device(device_id) do
              %{user_id: ^user_id, revoked_at: nil} -> true
              _ -> false
            end
          else
            false
          end

        {:ok, session, token} =
          Accounts.create_session(user.id, %{
            device_id: if(device_verified, do: device_id),
            remember_me: remember_me,
            ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
            user_agent: get_req_header(conn, "user-agent") |> List.first()
          })

        master_key = Encryption.get_user_encrypted_master_key(user.id)

        kdf_migration_required =
          master_key != nil and master_key.kdf_params != nil and
            master_key.kdf_params != @target_kdf_params

        keys =
          if device_verified do
            Encryption.get_login_keys(user.id, device_id)
            |> format_login_keys()
          end

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

        response =
          if kdf_migration_required do
            Map.merge(response, %{
              kdf_migration_required: true,
              target_kdf_params: @target_kdf_params
            })
          else
            response
          end

        conn
        |> set_session_cookie(token, remember_me)
        |> json(response)

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

  def me(conn, _params) do
    user = Accounts.get_user(conn.assigns.current_user_id)
    session = conn.assigns.current_session
    device_verified = conn.assigns.device_verified

    master_key = Encryption.get_user_encrypted_master_key(user.id)
    identity_pub = Encryption.get_user_identity_public_key(user.id)

    keys =
      if device_verified and session.device_id do
        Encryption.get_login_keys(user.id, session.device_id)
        |> format_login_keys()
      end

    response = %{
      user: %{
        id: user.id,
        email: user.email,
        name: user.name,
        encryption_setup_at: user.encryption_setup_at
      },
      session_id: session.id,
      device_id: session.device_id,
      device_verified: device_verified,
      remember_me: session.remember_me,
      expires_at: session.expires_at,
      auth_type: master_key && master_key.auth_type,
      identity_signing_public_key: identity_pub && encode_binary(identity_pub.signing_public_key)
    }

    response = if keys, do: Map.put(response, :keys, keys), else: response

    json(conn, response)
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
               encrypted_umk: decode_binary!(params["new_encrypted_umk"]),
               umk_nonce: decode_binary!(params["new_nonce"]),
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
    user = Accounts.get_user(conn.assigns.current_user_id)

    case Accounts.verify_auth_key(user.email, auth_key) do
      {:ok, _} ->
        json(conn, %{ok: true})

      {:error, :invalid_credentials} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_credentials"})
    end
  end

  operation(:pop_challenge,
    summary: "Request a PoP challenge nonce",
    responses: [
      ok: {"Challenge response", "application/json", Schemas.PopChallengeResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  def pop_challenge(conn, _params) do
    user_id = conn.assigns.current_user_id
    device_id = get_req_header(conn, "x-pop-device-id") |> List.first()

    cond do
      device_id == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "missing_device_id"})

      not Accounts.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
        case Accounts.create_pop_challenge(user_id, device_id) do
          {:ok, challenge} ->
            json(conn, %{challenge: Base.url_encode64(challenge, padding: false)})

          {:error, _} ->
            conn |> put_status(:unprocessable_entity) |> json(%{error: "challenge_creation_failed"})
        end
    end
  end

  operation(:logout,
    summary: "Logout current session",
    responses: [
      ok: {"Logout result", "application/json", Schemas.OkResponse}
    ]
  )

  def logout(conn, _params) do
    session = conn.assigns.current_session
    Accounts.delete_session(session.id)

    conn
    |> delete_session_cookie()
    |> json(%{ok: true})
  end

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
    identity_key = Encryption.get_user_encrypted_identity_key(user_id)
    identity_pub = Encryption.get_user_identity_public_key(user_id)

    if master_key == nil or master_key.recovery_encrypted_umk == nil do
      conn |> put_status(:not_found) |> json(%{error: "no_recovery_data"})
    else
      json(conn, %{
        recovery_encrypted_umk: encode_binary(master_key.recovery_encrypted_umk),
        recovery_nonce: encode_binary(master_key.recovery_nonce),
        encrypted_ecdh_private: encode_binary(identity_key && identity_key.encrypted_ecdh_private),
        encrypted_ecdh_private_nonce: encode_binary(identity_key && identity_key.encrypted_ecdh_private_nonce),
        encrypted_signing_private: encode_binary(identity_key && identity_key.encrypted_signing_private),
        encrypted_signing_private_nonce: encode_binary(identity_key && identity_key.encrypted_signing_private_nonce),
        ecdh_public_key: encode_binary(identity_pub && identity_pub.ecdh_public_key),
        signing_public_key: encode_binary(identity_pub && identity_pub.signing_public_key)
      })
    end
  end

  operation(:recovery_challenge,
    summary: "Request a recovery challenge",
    request_body: {"Recovery challenge request", "application/json", Schemas.RecoveryChallengeRequest},
    responses: [
      ok: {"Challenge response", "application/json", Schemas.RecoveryChallengeResponse}
    ]
  )

  def recovery_challenge(conn, %{"email" => email}) do
    case Accounts.get_user_by_email(email) do
      nil ->
        # Anti-enumeration: return a dummy challenge
        dummy = :crypto.strong_rand_bytes(32)
        json(conn, %{challenge: Base.url_encode64(dummy, padding: false)})

      user ->
        case Accounts.create_recovery_challenge(user.id) do
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
    request_body: {"Recovery session request", "application/json", Schemas.RecoverySessionRequest},
    responses: [
      ok: {"Recovery session", "application/json", Schemas.RecoverySessionResponse},
      unauthorized: {"Invalid recovery", "application/json", Schemas.ErrorResponse}
    ]
  )

  def recovery_session(conn, params) do
    email = params["email"]
    timestamp = params["timestamp"]

    with true <- is_integer(timestamp),
         {:ok, challenge} <- decode_binary(params["challenge"]),
         {:ok, signature} <- decode_binary(params["signature"]),
         %{} = user <- Accounts.get_user_by_email(email),
         :ok <- Accounts.verify_recovery_session(user.id, challenge, signature, timestamp) do
      {:ok, session, token} =
        Accounts.create_session(user.id, %{
          is_recovery: true,
          ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
          user_agent: get_req_header(conn, "user-agent") |> List.first()
        })

      conn
      |> set_session_cookie(token, false)
      |> json(%{
        user: %{id: user.id, email: user.email, name: user.name},
        session_id: session.id,
        is_recovery: true
      })
    else
      _ ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_or_expired_recovery_request"})
    end
  end

  operation(:password_set,
    summary: "Set password after recovery (recovery session required)",
    request_body: {"Password set params", "application/json", Schemas.PasswordSetRequest},
    responses: [
      ok: {"Password set", "application/json", Schemas.OkResponse},
      forbidden: {"Not a recovery session", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Update failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def password_set(conn, params) do
    session = conn.assigns.current_session

    if not session.is_recovery do
      conn |> put_status(:forbidden) |> json(%{error: "recovery_session_required"})
    else
      user_id = conn.assigns.current_user_id

      case Encryption.update_master_key_for_password_set(user_id, %{
             auth_key_hash: Bcrypt.hash_pwd_salt(params["new_auth_key"]),
             salt: decode_binary!(params["new_salt"]),
             encrypted_umk: decode_binary!(params["new_encrypted_umk"]),
             umk_nonce: decode_binary!(params["new_umk_nonce"]),
             kdf_params: @target_kdf_params
           }) do
        {:ok, _} ->
          Accounts.delete_all_sessions(user_id)

          {:ok, new_session, token} =
            Accounts.create_session(user_id, %{
              is_recovery: true,
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: get_req_header(conn, "user-agent") |> List.first()
            })

          conn
          |> set_session_cookie(token, false)
          |> json(%{ok: true, session_id: new_session.id})

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "password_set_failed"})
      end
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:change_password,
    summary: "Change password (PoP required)",
    request_body: {"Password change params", "application/json", Schemas.ChangePasswordRequest},
    responses: [
      ok: {"Password changed", "application/json", Schemas.OkResponse},
      unauthorized: {"Invalid current password", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Update failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def change_password(conn, params) do
    user_id = conn.assigns.current_user_id
    user = Accounts.get_user(user_id)
    session = conn.assigns.current_session

    case Accounts.verify_auth_key(user.email, params["current_auth_key"]) do
      {:error, :invalid_credentials} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_credentials"})

      {:ok, _} ->
        case Encryption.update_master_key_for_password_set(user_id, %{
               auth_key_hash: Bcrypt.hash_pwd_salt(params["new_auth_key"]),
               salt: decode_binary!(params["new_salt"]),
               encrypted_umk: decode_binary!(params["new_encrypted_umk"]),
               umk_nonce: decode_binary!(params["new_umk_nonce"]),
               kdf_params: @target_kdf_params
             }) do
          {:ok, _} ->
            Accounts.delete_other_sessions(user_id, session.id)
            json(conn, %{ok: true})

          {:error, _} ->
            conn |> put_status(:unprocessable_entity) |> json(%{error: "password_change_failed"})
        end
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:regenerate_recovery_key,
    summary: "Regenerate recovery key (PoP required)",
    request_body: {"Recovery key params", "application/json", Schemas.RegenerateRecoveryKeyRequest},
    responses: [
      ok: {"Recovery key updated", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Update failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def regenerate_recovery_key(conn, params) do
    user_id = conn.assigns.current_user_id

    case Encryption.update_recovery_key(user_id, %{
           recovery_encrypted_umk: decode_binary!(params["new_recovery_encrypted_umk"]),
           recovery_nonce: decode_binary!(params["new_recovery_nonce"])
         }) do
      {:ok, _} ->
        json(conn, %{ok: true})

      {:error, _} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "recovery_key_update_failed"})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:password_reset_request,
    summary: "Request a password reset email",
    request_body: {"Reset request", "application/json", Schemas.PasswordResetRequestBody},
    responses: [
      ok: {"Request accepted", "application/json", Schemas.OkResponse}
    ]
  )

  def password_reset_request(conn, %{"email" => email}) do
    case Accounts.get_user_by_email(email) do
      nil ->
        json(conn, %{ok: true})

      user ->
        if Accounts.can_send_password_reset?(user.id) do
          case Accounts.create_password_reset_token(user.id) do
            {:ok, token} -> RefMD.Mailer.send_password_reset(user.email, token)
            _ -> :ok
          end
        end

        json(conn, %{ok: true})
    end
  end

  def password_reset_request(conn, _params) do
    json(conn, %{ok: true})
  end

  operation(:password_reset_verify,
    summary: "Verify password reset token and create session",
    request_body: {"Token verification", "application/json", Schemas.PasswordResetVerifyBody},
    responses: [
      ok: {"Session created", "application/json", Schemas.PasswordResetVerifyResponse},
      unprocessable_entity: {"Invalid token", "application/json", Schemas.ErrorResponse}
    ]
  )

  def password_reset_verify(conn, %{"token" => token_b64}) do
    with {:ok, raw_token} <- Base.url_decode64(token_b64, padding: false),
         {:ok, user_id} <- Accounts.verify_password_reset_token(raw_token) do
      user = Accounts.get_user(user_id)

      {:ok, session, token} =
        Accounts.create_session(user_id, %{
          ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
          user_agent: get_req_header(conn, "user-agent") |> List.first()
        })

      conn
      |> set_session_cookie(token, false)
      |> json(%{
        user: %{id: user.id, email: user.email, name: user.name},
        session_id: session.id
      })
    else
      :error ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_or_expired_token"})

      {:error, :invalid_token} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_or_expired_token"})
    end
  end

  # ── Helpers ────────────────────────────────────

  defp set_session_cookie(conn, token, remember_me) do
    token_base64 = Base.url_encode64(token, padding: false)
    max_age = if remember_me, do: 30 * 24 * 60 * 60, else: nil

    same_site =
      case Application.get_env(:refmd, :samesite_mode, "lax") do
        "none" -> "None"
        _ -> "Lax"
      end

    opts = [
      path: "/api",
      http_only: true,
      secure: Application.get_env(:refmd, :cookie_secure, conn.scheme == :https) or same_site == "None",
      same_site: same_site
    ]

    opts = if max_age, do: [{:max_age, max_age} | opts], else: opts
    put_resp_cookie(conn, "_refmd_session", token_base64, opts)
  end

  defp delete_session_cookie(conn) do
    delete_resp_cookie(conn, "_refmd_session", path: "/api")
  end

  defp decode_binary(base64) when is_binary(base64) do
    case Base.url_decode64(base64, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_binary(_), do: {:error, :invalid_base64}

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  defp valid_uuid?(str) when is_binary(str), do: Regex.match?(@uuid_regex, str)
  defp valid_uuid?(_), do: false

  defp decode_required(nil), do: :error
  defp decode_required(val) when is_binary(val), do: {:ok, Base.url_decode64!(val, padding: false)}

  defp decode_binary!(nil), do: nil
  defp decode_binary!(val) when is_binary(val), do: Base.url_decode64!(val, padding: false)

  defp format_login_keys(keys) do
    mk = keys.encrypted_master_key
    ik = keys.encrypted_identity_key

    result = %{
      encrypted_ecdh_private: encode_binary(ik && ik.encrypted_ecdh_private),
      encrypted_ecdh_private_nonce: encode_binary(ik && ik.encrypted_ecdh_private_nonce),
      encrypted_signing_private: encode_binary(ik && ik.encrypted_signing_private),
      encrypted_signing_private_nonce: encode_binary(ik && ik.encrypted_signing_private_nonce)
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

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp format_errors(_), do: %{}
end
