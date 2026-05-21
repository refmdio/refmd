defmodule RefMDWeb.PasswordController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Auth, Encryption, Users}
  alias RefMD.Crypto.Encoding
  alias RefMDWeb.Schemas

  @target_kdf_params %{
    "algorithm" => "argon2id",
    "memory" => 65_536,
    "iterations" => 3,
    "parallelism" => 4,
    "hash_length" => 32
  }

  operation(:password_set,
    summary: "Set password after recovery (recovery session required)",
    request_body: {"Password set params", "application/json", Schemas.PasswordSetRequest},
    responses: [
      ok: {"Password set", "application/json", Schemas.PasswordSetResponse},
      forbidden: {"Not a recovery session", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Update failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec password_set(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def password_set(conn, params) do
    session = conn.assigns.current_session

    if session.is_recovery do
      user_id = conn.assigns.current_user_id

      case Encryption.update_master_key_for_password_set(user_id, %{
             auth_key_hash: Bcrypt.hash_pwd_salt(params["new_auth_key"]),
             salt: decode_optional_binary(params["new_salt"]),
             encrypted_umk: decode_optional_binary(params["new_encrypted_umk"]),
             umk_nonce: decode_optional_binary(params["new_umk_nonce"]),
             kdf_params: @target_kdf_params
           }) do
        {:ok, _} ->
          Auth.delete_all_sessions(user_id)

          {:ok, new_session, token} =
            Auth.create_session(user_id, %{
              id: session.id,
              is_recovery: true,
              device_registration_id: session.device_registration_id,
              recovery_session_transcript_hash: session.recovery_session_transcript_hash,
              recovery_capability_hash: session.recovery_capability_hash,
              pending_registration_binding_hash: session.pending_registration_binding_hash,
              target_key_checkpoint_sequence: session.target_key_checkpoint_sequence,
              target_key_checkpoint_hash: session.target_key_checkpoint_hash,
              candidate_user_checkpoint_sequence: session.candidate_user_checkpoint_sequence,
              candidate_user_checkpoint_hash: session.candidate_user_checkpoint_hash,
              candidate_user_event_head_sequence: session.candidate_user_event_head_sequence,
              candidate_user_event_head_hash: session.candidate_user_event_head_hash,
              recovered_identity_signing_key_id: session.recovered_identity_signing_key_id,
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: get_req_header(conn, "user-agent") |> List.first()
            })

          conn
          |> set_session_cookie(token, false)
          |> json(%{ok: true, session_id: new_session.id})

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "password_set_failed"})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "recovery_session_required"})
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

  @spec change_password(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def change_password(conn, params) do
    user_id = conn.assigns.current_user_id
    user = Users.get_user(user_id)
    session = conn.assigns.current_session

    case Auth.verify_auth_key(user.email, params["current_auth_key"]) do
      {:error, :invalid_credentials} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_credentials"})

      {:ok, _} ->
        case Encryption.update_master_key_for_password_set(user_id, %{
               auth_key_hash: Bcrypt.hash_pwd_salt(params["new_auth_key"]),
               salt: decode_optional_binary(params["new_salt"]),
               encrypted_umk: decode_optional_binary(params["new_encrypted_umk"]),
               umk_nonce: decode_optional_binary(params["new_umk_nonce"]),
               kdf_params: @target_kdf_params
             }) do
          {:ok, _} ->
            Auth.delete_other_sessions(user_id, session.id)
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
    request_body:
      {"Recovery key params", "application/json", Schemas.RegenerateRecoveryKeyRequest},
    responses: [
      ok: {"Recovery key updated", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Update failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec regenerate_recovery_key(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def regenerate_recovery_key(conn, params) do
    user_id = conn.assigns.current_user_id

    case Encryption.update_recovery_key(user_id, %{
           recovery_encrypted_umk: decode_optional_binary(params["new_recovery_encrypted_umk"]),
           recovery_nonce: decode_optional_binary(params["new_recovery_nonce"]),
           recovery_authorization_public_material:
             params["new_recovery_authorization_public_material"],
           recovery_authorization_key_id: params["new_recovery_authorization_key_id"]
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

  @spec password_reset_request(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def password_reset_request(conn, %{"email" => email}) do
    case Users.get_user_by_email(email) do
      nil ->
        :ok

      user ->
        maybe_send_password_reset(user)
    end

    json(conn, %{ok: true})
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

  @spec password_reset_verify(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def password_reset_verify(conn, %{"token" => token_b64}) do
    with {:ok, raw_token} <- decode_base64url(token_b64),
         {:ok, user_id} <- Auth.verify_password_reset_token(raw_token) do
      user = Users.get_user(user_id)

      {:ok, session, token} =
        Auth.create_session(user_id, %{
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

  defp decode_base64url(value) when is_binary(value) do
    {:ok, Encoding.decode_base64url!(value)}
  rescue
    ArgumentError -> :error
  end

  defp decode_base64url(_), do: :error

  defp maybe_send_password_reset(user) do
    if Auth.can_send_password_reset?(user.id) do
      case Auth.create_password_reset_token(user.id) do
        {:ok, token} -> RefMD.Mailer.send_password_reset(user.email, token)
        _ -> :ok
      end
    end
  end
end
