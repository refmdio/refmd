defmodule RefMDWeb.AuthController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Accounts, Encryption, Workspaces}
  alias RefMDWeb.Schemas

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

  def register(conn, params) do
    Ecto.Multi.new()
    |> Ecto.Multi.run(:user, fn _repo, _changes ->
      Accounts.create_user(%{
        email: params["email"],
        name: params["name"]
      })
    end)
    |> Ecto.Multi.run(:settings, fn _repo, %{user: user} ->
      Accounts.create_user_settings(user.id)
    end)
    |> Ecto.Multi.run(:identity_public_key, fn _repo, %{user: user} ->
      Encryption.create_user_identity_public_key(%{
        user_id: user.id,
        ecdh_public_key: decode_binary!(params["ecdh_public_key"]),
        signing_public_key: decode_binary!(params["signing_public_key"])
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
        kdf_params: params["kdf_params"] || @target_kdf_params,
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
      Workspaces.create_default_workspace(user.id, "My Workspace")
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

        keys =
          if device_verified do
            Encryption.get_login_keys(user.id, device_id)
            |> format_login_keys()
          end

        master_key = Encryption.get_user_encrypted_master_key(user.id)

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
          keys: keys
        }

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

    keys =
      if device_verified and session.device_id do
        Encryption.get_login_keys(user.id, session.device_id)
        |> format_login_keys()
      end

    json(conn, %{
      user: %{
        id: user.id,
        email: user.email,
        name: user.name,
        encryption_setup_at: user.encryption_setup_at
      },
      session_id: session.id,
      device_id: session.device_id,
      device_verified: device_verified,
      expires_at: session.expires_at,
      auth_type: master_key && master_key.auth_type,
      keys: keys
    })
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

  # ── Helpers ────────────────────────────────────

  defp set_session_cookie(conn, token, remember_me) do
    token_base64 = Base.url_encode64(token, padding: false)
    max_age = if remember_me, do: 30 * 24 * 60 * 60, else: nil

    opts = [
      path: "/api",
      http_only: true,
      secure: conn.scheme == :https,
      same_site: "Lax"
    ]

    opts = if max_age, do: [{:max_age, max_age} | opts], else: opts
    put_resp_cookie(conn, "_refmd_session", token_base64, opts)
  end

  defp delete_session_cookie(conn) do
    delete_resp_cookie(conn, "_refmd_session", path: "/api")
  end

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp decode_binary!(nil), do: nil

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
