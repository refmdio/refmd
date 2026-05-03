defmodule RefMDWeb.GuestInvitationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Auth
  alias RefMD.Users
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug RequireRBAC,
       [permission: "guest:invite", not_member_status: :not_found]
       when action in [:index, :create, :delete]

  @max_expires_days 30
  @user_session_cookie "_refmd_session"
  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  operation(:create,
    summary: "Create a guest invitation",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Guest invitation params", "application/json", Schemas.CreateGuestInvitationRequest},
    responses: [
      created: {"Created guest invitation", "application/json", Schemas.GuestInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    workspace_id = conn.assigns.workspace_id
    user_id = conn.assigns.current_user_id
    actor_role = conn.assigns.workspace_role

    with {:ok, validated} <- validate_create_params(params, workspace_id, user_id),
         {:ok, invitation} <-
           Workspaces.create_guest_invitation(Map.put(validated, :actor_role, actor_role)) do
      conn
      |> put_status(:created)
      |> json(serialize_invitation(invitation))
    else
      {:error, reason} -> handle_create_error(conn, reason)
    end
  end

  operation(:index,
    summary: "List guest invitations",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Guest invitation list", "application/json", Schemas.GuestInvitationsListResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    invitations = Workspaces.list_guest_invitations(conn.assigns.workspace_id)
    json(conn, %{invitations: invitations})
  end

  operation(:delete,
    summary: "Revoke a guest invitation",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      invitation_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      no_content: {"Revoked", "application/json", nil},
      bad_request: {"Invalid ID format", "application/json", Schemas.ErrorResponse},
      conflict: {"Guest invites disabled", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"invitation_id" => invitation_id}) do
    if Regex.match?(@uuid_regex, invitation_id) do
      case Workspaces.revoke_guest_invitation(
             conn.assigns.workspace_id,
             invitation_id,
             conn.assigns.current_user_id
           ) do
        {:ok, _} ->
          send_resp(conn, :no_content, "")

        {:error, :guest_invites_disabled} ->
          conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

        {:error, :permission_denied} ->
          conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})

        {:error, :serialization_failure} ->
          conn |> put_status(:conflict) |> json(%{error: "serialization_failure"})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "not_found"})
      end
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_invitation_id_format"})
    end
  end

  operation(:redeem,
    summary: "Redeem a guest invitation",
    request_body:
      {"Redeem guest invitation params", "application/json", Schemas.RedeemGuestInvitationRequest},
    responses: [
      ok:
        {"Redeemed guest invitation", "application/json", Schemas.RedeemGuestInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec redeem(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def redeem(conn, params) do
    with :ok <- reject_active_user_session(conn),
         {:ok, validated} <- validate_redeem_params(params),
         {:ok, token_hash} <- compute_token_hash(validated.token),
         {:ok, result} <-
           Workspaces.redeem_guest_invitation(token_hash, validated, %{
             ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
             user_agent: get_req_header(conn, "user-agent") |> List.first()
           }) do
      conn
      |> set_session_cookie(result.session_token, false)
      |> json(serialize_redeem_result(result))
    else
      {:error, reason} -> handle_redeem_error(conn, reason)
    end
  end

  defp reject_active_user_session(conn),
    do: conn |> fetch_user_session_cookie() |> validate_session_cookie()

  defp fetch_user_session_cookie(conn) do
    conn
    |> get_req_header("cookie")
    |> parse_cookies()
    |> Map.get(@user_session_cookie)
  end

  defp parse_cookies([cookie_header | _]) do
    cookie_header
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [key, value] -> Map.put(acc, key, value)
        _ -> acc
      end
    end)
  end

  defp parse_cookies(_headers), do: %{}

  defp validate_session_cookie(token) when is_binary(token) do
    case Auth.get_valid_session_by_token_base64(token) do
      {:ok, session} -> validate_existing_session_user(session.user_id)
      _ -> :ok
    end
  end

  defp validate_session_cookie(_token), do: :ok

  defp validate_existing_session_user(user_id) do
    case Users.get_user(user_id) do
      %{account_type: "guest"} -> :ok
      _user -> {:error, :active_user_session}
    end
  end

  defp validate_create_params(params, workspace_id, user_id) do
    with {:ok, encrypted_kek} <- decode_base64url(params["encrypted_kek"], :encrypted_kek),
         {:ok, kek_nonce} <- decode_base64url(params["kek_nonce"], :kek_nonce),
         :ok <- validate_byte_length(encrypted_kek, 48, :invalid_encrypted_kek_length),
         :ok <- validate_byte_length(kek_nonce, 24, :invalid_nonce_length),
         :ok <- validate_token_hash(params["token_hash"]),
         :ok <- validate_token_prefix(params["token_prefix"]),
         :ok <- validate_invitation_id(params["invitation_id"]),
         :ok <- validate_target_scope(params["target_scope"]),
         :ok <- validate_permission(params["permission"]),
         :ok <- validate_target_document_id(params["target_scope"], params["target_document_id"]),
         :ok <- validate_positive_integer(params["kek_version"], :invalid_kek_version),
         :ok <-
           validate_optional_positive_integer(params["max_redemptions"], :invalid_max_redemptions),
         :ok <- validate_expires_at(params["expires_at"]) do
      {:ok,
       %{
         workspace_id: workspace_id,
         invitation_id: params["invitation_id"],
         token_hash: params["token_hash"],
         token_prefix: params["token_prefix"],
         target_scope: params["target_scope"],
         target_document_id: params["target_document_id"],
         permission: params["permission"],
         encrypted_kek: encrypted_kek,
         kek_nonce: kek_nonce,
         kek_version: params["kek_version"],
         max_redemptions: params["max_redemptions"],
         invited_by: user_id,
         expires_at: parse_expires_at(params["expires_at"])
       }}
    end
  end

  defp validate_redeem_params(params) do
    with {:ok, token} <- decode_token(params["token"]),
         :ok <- validate_guest_user_id(params["guest_user_id"]),
         {:ok, signing_key} <-
           decode_base64url(params["device_signing_pub_key"], :device_signing_pub_key),
         {:ok, encryption_key} <-
           decode_base64url(params["device_encryption_pub_key"], :device_encryption_pub_key),
         {:ok, identity_signing_key} <-
           decode_base64url(params["identity_signing_pub_key"], :identity_signing_pub_key),
         {:ok, identity_encryption_key} <-
           decode_base64url(params["identity_encryption_pub_key"], :identity_encryption_pub_key),
         {:ok, identity_signature} <-
           decode_base64url(params["identity_signature"], :identity_signature),
         {:ok, client_nonce} <- decode_base64url(params["client_nonce"], :client_nonce),
         {:ok, recovery_encrypted_umk} <-
           decode_base64url(params["recovery_encrypted_umk"], :recovery_encrypted_umk),
         {:ok, recovery_nonce} <- decode_base64url(params["recovery_nonce"], :recovery_nonce),
         {:ok, encrypted_identity_encryption_private} <-
           decode_base64url(
             params["encrypted_identity_encryption_private"],
             :encrypted_identity_encryption_private
           ),
         {:ok, encrypted_identity_encryption_private_nonce} <-
           decode_base64url(
             params["encrypted_identity_encryption_private_nonce"],
             :encrypted_identity_encryption_private_nonce
           ),
         {:ok, encrypted_identity_signing_private} <-
           decode_base64url(
             params["encrypted_identity_signing_private"],
             :encrypted_identity_signing_private
           ),
         {:ok, encrypted_identity_signing_private_nonce} <-
           decode_base64url(
             params["encrypted_identity_signing_private_nonce"],
             :encrypted_identity_signing_private_nonce
           ),
         :ok <- validate_byte_length(signing_key, 32, :invalid_signing_public_key_length),
         :ok <- validate_byte_length(encryption_key, 32, :invalid_encryption_public_key_length),
         :ok <-
           validate_byte_length(
             identity_signing_key,
             32,
             :invalid_identity_signing_public_key_length
           ),
         :ok <-
           validate_byte_length(
             identity_encryption_key,
             32,
             :invalid_identity_encryption_public_key_length
           ),
         :ok <- validate_byte_length(identity_signature, 64, :invalid_identity_signature_length),
         :ok <- validate_byte_length(client_nonce, 16, :invalid_client_nonce_length),
         :ok <-
           validate_byte_length(
             recovery_encrypted_umk,
             48,
             :invalid_recovery_encrypted_umk_length
           ),
         :ok <- validate_byte_length(recovery_nonce, 24, :invalid_recovery_nonce_length),
         :ok <-
           validate_byte_length(
             encrypted_identity_encryption_private,
             48,
             :invalid_encrypted_identity_encryption_private_length
           ),
         :ok <-
           validate_byte_length(
             encrypted_identity_encryption_private_nonce,
             24,
             :invalid_encrypted_identity_encryption_private_nonce_length
           ),
         :ok <-
           validate_byte_length(
             encrypted_identity_signing_private,
             48,
             :invalid_encrypted_identity_signing_private_length
           ),
         :ok <-
           validate_byte_length(
             encrypted_identity_signing_private_nonce,
             24,
             :invalid_encrypted_identity_signing_private_nonce_length
           ),
         :ok <- validate_signing_key(signing_key),
         :ok <- validate_encryption_key(encryption_key),
         :ok <- validate_signing_key(identity_signing_key),
         :ok <- validate_encryption_key(identity_encryption_key),
         :ok <- validate_optional_device_name(params["device_name"]),
         :ok <- validate_optional_device_type(params["device_type"]) do
      {:ok,
       %{
         token: token,
         guest_user_id: params["guest_user_id"],
         device_signing_pub_key: signing_key,
         device_encryption_pub_key: encryption_key,
         identity_signing_pub_key: identity_signing_key,
         identity_encryption_pub_key: identity_encryption_key,
         identity_signature: identity_signature,
         client_nonce: client_nonce,
         recovery_encrypted_umk: recovery_encrypted_umk,
         recovery_nonce: recovery_nonce,
         encrypted_identity_encryption_private: encrypted_identity_encryption_private,
         encrypted_identity_encryption_private_nonce: encrypted_identity_encryption_private_nonce,
         encrypted_identity_signing_private: encrypted_identity_signing_private,
         encrypted_identity_signing_private_nonce: encrypted_identity_signing_private_nonce,
         device_name: params["device_name"],
         device_type: params["device_type"]
       }}
    end
  end

  defp serialize_invitation(invitation) do
    %{
      invitation_id: invitation.id,
      workspace_id: invitation.workspace_id,
      token_prefix: invitation.token_prefix,
      target_scope: invitation.target_scope,
      target_document_id: invitation.target_document_id,
      permission: invitation.permission,
      invited_by: invitation.invited_by,
      kek_version: invitation.kek_version,
      max_redemptions: invitation.max_redemptions,
      redemption_count: invitation.redemption_count,
      expires_at: invitation.expires_at,
      created_at: invitation.created_at,
      revoked_at: invitation.revoked_at
    }
  end

  defp serialize_redeem_result(result) do
    %{
      workspace_id: result.workspace_id,
      workspace_name: result.workspace_name,
      invitation_id: result.invitation_id,
      target_scope: result.target_scope,
      target_document_id: result.target_document_id,
      permission: result.permission,
      guest_user_id: result.guest_user_id,
      guest_device_id: result.guest_device_id,
      encrypted_kek: Base.url_encode64(result.encrypted_kek, padding: false),
      kek_nonce: Base.url_encode64(result.kek_nonce, padding: false),
      kek_version: result.kek_version
    }
  end

  defp decode_base64url(nil, field), do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) when not is_binary(value),
    do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, {:invalid_format, field}}
    end
  end

  defp decode_token(nil), do: {:error, :missing_token}
  defp decode_token(token) when not is_binary(token), do: {:error, :invalid_token_format}

  defp decode_token(token) do
    case Base.url_decode64(token, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 32 -> {:ok, bytes}
      {:ok, _bytes} -> {:error, :invalid_token_length}
      :error -> {:error, :invalid_token_format}
    end
  end

  defp compute_token_hash(token_bytes) do
    {:ok, Base.url_encode64(:crypto.hash(:sha256, token_bytes), padding: false)}
  end

  defp validate_byte_length(bytes, expected, error_atom) do
    if byte_size(bytes) == expected, do: :ok, else: {:error, error_atom}
  end

  defp validate_signing_key(key) do
    if RefMD.Crypto.valid_ed25519_public_key?(key),
      do: :ok,
      else: {:error, :invalid_signing_public_key}
  end

  defp validate_encryption_key(key) do
    if RefMD.Crypto.valid_x25519_public_key?(key),
      do: :ok,
      else: {:error, :invalid_encryption_public_key}
  end

  defp validate_token_hash(nil), do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) when not is_binary(hash),
    do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, hash),
      do: :ok,
      else: {:error, :invalid_token_hash_format}
  end

  defp validate_token_prefix(nil), do: {:error, :invalid_token_prefix}

  defp validate_token_prefix(prefix) when not is_binary(prefix),
    do: {:error, :invalid_token_prefix}

  defp validate_token_prefix(prefix) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{4}$/, prefix),
      do: :ok,
      else: {:error, :invalid_token_prefix}
  end

  defp validate_invitation_id(nil), do: {:error, :invalid_invitation_id_format}

  defp validate_invitation_id(id) when not is_binary(id),
    do: {:error, :invalid_invitation_id_format}

  defp validate_invitation_id(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_invitation_id_format}
  end

  defp validate_guest_user_id(nil), do: {:error, :invalid_guest_user_id_format}

  defp validate_guest_user_id(id) when not is_binary(id),
    do: {:error, :invalid_guest_user_id_format}

  defp validate_guest_user_id(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_guest_user_id_format}
  end

  defp validate_target_scope(scope) when scope in ["workspace", "document", "folder"], do: :ok
  defp validate_target_scope(_scope), do: {:error, :invalid_target_scope}

  defp validate_permission(permission) when permission in ["view", "edit"], do: :ok
  defp validate_permission(_permission), do: {:error, :invalid_permission}

  defp validate_target_document_id("workspace", nil), do: :ok

  defp validate_target_document_id(scope, id)
       when scope in ["document", "folder"] and is_binary(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_target_document_id}
  end

  defp validate_target_document_id(_scope, _id), do: {:error, :invalid_target_document_id}

  defp validate_positive_integer(value, _error_atom) when is_integer(value) and value > 0, do: :ok
  defp validate_positive_integer(_value, error_atom), do: {:error, error_atom}

  defp validate_optional_positive_integer(nil, _error_atom), do: :ok

  defp validate_optional_positive_integer(value, error_atom),
    do: validate_positive_integer(value, error_atom)

  defp validate_optional_device_name(nil), do: :ok
  defp validate_optional_device_name(name) when is_binary(name) and byte_size(name) > 0, do: :ok
  defp validate_optional_device_name(_name), do: {:error, :invalid_device_name}

  defp validate_optional_device_type(nil), do: :ok
  defp validate_optional_device_type(type) when type in ["browser", "desktop", "mobile"], do: :ok
  defp validate_optional_device_type(_type), do: {:error, :invalid_device_type}

  defp validate_expires_at(nil), do: :ok

  defp validate_expires_at(expires_at_str) when not is_binary(expires_at_str),
    do: {:error, :invalid_expires_at}

  defp validate_expires_at(expires_at_str) do
    case DateTime.from_iso8601(expires_at_str) do
      {:ok, dt, _} ->
        now = DateTime.utc_now()
        max_dt = DateTime.add(now, @max_expires_days * 86_400)

        cond do
          DateTime.compare(dt, now) != :gt -> {:error, :invalid_expires_at}
          DateTime.compare(dt, max_dt) == :gt -> {:error, :invalid_expires_at}
          true -> :ok
        end

      _ ->
        {:error, :invalid_expires_at}
    end
  end

  defp parse_expires_at(nil), do: nil

  defp parse_expires_at(str) do
    {:ok, dt, _} = DateTime.from_iso8601(str)
    dt
  end

  defp handle_create_error(conn, {:invalid_format, _field}),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_format"})

  defp handle_create_error(conn, :workspace_not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp handle_create_error(conn, :guest_invites_disabled),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

  defp handle_create_error(conn, :kek_rotation_in_progress),
    do: conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})

  defp handle_create_error(conn, :encryption_setup_incomplete),
    do: conn |> put_status(:conflict) |> json(%{error: "encryption_setup_incomplete"})

  defp handle_create_error(conn, :kek_version_mismatch),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "kek_version_mismatch"})

  defp handle_create_error(conn, :invalid_target_document),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_target_document"})

  defp handle_create_error(conn, :token_hash_already_exists),
    do: conn |> put_status(:conflict) |> json(%{error: "token_hash_already_exists"})

  defp handle_create_error(conn, :id_already_exists),
    do: conn |> put_status(:conflict) |> json(%{error: "id_already_exists"})

  defp handle_create_error(conn, :permission_escalation),
    do: conn |> put_status(:forbidden) |> json(%{error: "permission_escalation"})

  defp handle_create_error(conn, :permission_denied),
    do: conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})

  defp handle_create_error(conn, :serialization_failure),
    do: conn |> put_status(:conflict) |> json(%{error: "serialization_failure"})

  defp handle_create_error(conn, reason),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})

  defp handle_redeem_error(conn, :missing_token),
    do: conn |> put_status(:bad_request) |> json(%{error: "missing_token"})

  defp handle_redeem_error(conn, :invalid_token_format),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_token_format"})

  defp handle_redeem_error(conn, :invalid_token_length),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_token_length"})

  defp handle_redeem_error(conn, :invalid_guest_user_id_format),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_guest_user_id_format"})

  defp handle_redeem_error(conn, {:invalid_format, _field}),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_format"})

  defp handle_redeem_error(conn, :not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp handle_redeem_error(conn, :guest_invites_disabled),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

  defp handle_redeem_error(conn, :guest_member_limit_reached),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_member_limit_reached"})

  defp handle_redeem_error(conn, :guest_user_id_conflict),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_user_id_conflict"})

  defp handle_redeem_error(conn, :active_user_session),
    do: conn |> put_status(:conflict) |> json(%{error: "active_user_session"})

  defp handle_redeem_error(conn, :kek_rotation_in_progress),
    do: conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})

  defp handle_redeem_error(conn, :invitation_revoked),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_revoked"})

  defp handle_redeem_error(conn, :invitation_expired),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_expired"})

  defp handle_redeem_error(conn, :invitation_redemptions_exhausted),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_redemptions_exhausted"})

  defp handle_redeem_error(conn, :invitation_kek_outdated),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_kek_outdated"})

  defp handle_redeem_error(conn, reason),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
end
