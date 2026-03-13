defmodule RefMDWeb.InvitationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug RequireRBAC,
       [permission: "member:invite", not_member_status: :not_found]
       when action in [:index, :create, :delete]

  # Accept uses no workspace RBAC (email-bound, PoP required)

  @max_expires_days 30

  # ── POST /api/workspaces/:workspace_id/invitations ──

  operation(:create,
    summary: "Create an invitation",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body: {"Invitation params", "application/json", Schemas.CreateInvitationRequest},
    responses: [
      created: {"Created invitation", "application/json", Schemas.InvitationResponse},
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
         validated = Map.put(validated, :actor_role, actor_role),
         {:ok, invitation} <- Workspaces.create_invitation(validated) do
      conn
      |> put_status(:created)
      |> json(serialize_invitation(invitation))
    else
      {:error, reason} -> handle_create_error(conn, reason)
    end
  end

  # ── GET /api/workspaces/:workspace_id/invitations ───

  operation(:index,
    summary: "List active invitations",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Invitation list", "application/json", Schemas.InvitationsListResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    invitations = Workspaces.list_active_invitations(conn.assigns.workspace_id)
    json(conn, %{invitations: invitations})
  end

  # ── DELETE /api/workspaces/:workspace_id/invitations/:invitation_id

  operation(:delete,
    summary: "Revoke an invitation",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      invitation_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      no_content: {"Revoked", "application/json", nil},
      bad_request: {"Invalid ID format", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"invitation_id" => invitation_id}) do
    if Regex.match?(@uuid_regex, invitation_id) do
      do_delete(conn, invitation_id)
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_invitation_id_format"})
    end
  end

  defp do_delete(conn, invitation_id) do
    workspace_id = conn.assigns.workspace_id

    case Workspaces.revoke_invitation(workspace_id, invitation_id) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  # ── POST /api/workspaces/invitations/accept ─────────

  operation(:accept,
    summary: "Accept an invitation",
    request_body: {"Accept params", "application/json", Schemas.AcceptInvitationRequest},
    responses: [
      ok: {"Accepted", "application/json", Schemas.AcceptInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec accept(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def accept(conn, %{"token" => token}) do
    with {:ok, token_bytes} <- decode_token(token),
         {:ok, token_hash} <- compute_token_hash(token_bytes) do
      user_id = conn.assigns.current_user_id
      user = RefMD.Repo.get!(RefMD.Users.User, user_id)

      case Workspaces.accept_invitation(token_hash, user_id, user.email) do
        {:ok, result} ->
          json(conn, serialize_acceptance(result))

        {:error, reason} ->
          handle_accept_error(conn, reason)
      end
    else
      {:error, reason} -> handle_accept_error(conn, reason)
    end
  end

  def accept(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_token"})
  end

  # ── Helpers ─────────────────────────────────────────

  defp validate_create_params(params, workspace_id, user_id) do
    with {:ok, encrypted_kek} <- decode_base64url(params["encrypted_kek"], :encrypted_kek),
         {:ok, kek_nonce} <- decode_base64url(params["kek_nonce"], :kek_nonce),
         :ok <- validate_byte_length(encrypted_kek, 48, :invalid_encrypted_kek_length),
         :ok <- validate_byte_length(kek_nonce, 24, :invalid_nonce_length),
         :ok <- validate_token_hash(params["token_hash"]),
         :ok <- validate_token_prefix(params["token_prefix"]),
         :ok <- validate_invitation_id(params["invitation_id"]),
         :ok <- validate_role_id(params["role_id"]),
         :ok <- validate_email(params["invited_email"]),
         :ok <- validate_expires_at(params["expires_at"]) do
      {:ok,
       %{
         workspace_id: workspace_id,
         invitation_id: params["invitation_id"],
         token_hash: params["token_hash"],
         token_prefix: params["token_prefix"],
         encrypted_kek: encrypted_kek,
         kek_nonce: kek_nonce,
         kek_version: params["kek_version"],
         role_id: params["role_id"],
         invited_by: user_id,
         invited_email: params["invited_email"],
         expires_at: parse_expires_at(params["expires_at"])
       }}
    end
  end

  defp decode_base64url(nil, field), do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) when not is_binary(value),
    do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, {:invalid_format, field}}
    end
  end

  defp validate_byte_length(bytes, expected, error_atom) do
    if byte_size(bytes) == expected, do: :ok, else: {:error, error_atom}
  end

  defp validate_token_hash(nil), do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) when not is_binary(hash),
    do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, hash) do
      case Base.url_decode64(hash, padding: false) do
        {:ok, bytes} when byte_size(bytes) == 32 -> :ok
        _ -> {:error, :invalid_token_hash_format}
      end
    else
      {:error, :invalid_token_hash_format}
    end
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
    if Regex.match?(@uuid_regex, id),
      do: :ok,
      else: {:error, :invalid_invitation_id_format}
  end

  defp validate_role_id(nil), do: :ok

  defp validate_role_id(role_id) when is_binary(role_id) do
    if Regex.match?(@uuid_regex, role_id),
      do: :ok,
      else: {:error, :invalid_role}
  end

  defp validate_role_id(_), do: {:error, :invalid_role}

  defp validate_email(nil), do: {:error, :invalid_email_format}
  defp validate_email(email) when not is_binary(email), do: {:error, :invalid_email_format}

  defp validate_email(email) do
    if Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, email),
      do: :ok,
      else: {:error, :invalid_email_format}
  end

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

  defp decode_token(token) when is_binary(token) do
    case Base.url_decode64(token, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 32 -> {:ok, bytes}
      {:ok, _} -> {:error, :invalid_token_length}
      :error -> {:error, :invalid_token_format}
    end
  end

  defp decode_token(_), do: {:error, :invalid_token_format}

  defp compute_token_hash(token_bytes) do
    hash = :crypto.hash(:sha256, token_bytes)
    {:ok, Base.url_encode64(hash, padding: false)}
  end

  defp serialize_invitation(invitation) do
    %{
      invitation_id: invitation.id,
      workspace_id: invitation.workspace_id,
      token_prefix: invitation.token_prefix,
      role_id: invitation.role_id,
      invited_email: invitation.invited_email,
      kek_version: invitation.kek_version,
      is_used: invitation.is_used,
      expires_at: invitation.expires_at,
      created_at: invitation.created_at
    }
  end

  defp serialize_acceptance(result) do
    %{
      workspace_id: result.workspace_id,
      workspace_name: result.workspace_name,
      role_name: result.role_name,
      invitation_id: result.invitation_id,
      encrypted_kek: Base.url_encode64(result.encrypted_kek, padding: false),
      kek_nonce: Base.url_encode64(result.kek_nonce, padding: false),
      kek_version: result.kek_version
    }
  end

  defp handle_create_error(conn, {:invalid_format, _field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_format"})
  end

  defp handle_create_error(conn, :invalid_encrypted_kek_length) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_encrypted_kek_length"})
  end

  defp handle_create_error(conn, :invalid_nonce_length) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_nonce_length"})
  end

  defp handle_create_error(conn, :invalid_token_hash_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_hash_format"})
  end

  defp handle_create_error(conn, :invalid_token_prefix) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_prefix"})
  end

  defp handle_create_error(conn, :invalid_invitation_id_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_invitation_id_format"})
  end

  defp handle_create_error(conn, :invalid_email_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_email_format"})
  end

  defp handle_create_error(conn, :invalid_expires_at) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_expires_at"})
  end

  defp handle_create_error(conn, :encryption_setup_incomplete) do
    conn |> put_status(:conflict) |> json(%{error: "encryption_setup_incomplete"})
  end

  defp handle_create_error(conn, :kek_rotation_in_progress) do
    conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})
  end

  defp handle_create_error(conn, :workspace_not_found) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_create_error(conn, :kek_version_mismatch) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "kek_version_mismatch"})
  end

  defp handle_create_error(conn, :no_default_role) do
    conn |> put_status(:internal_server_error) |> json(%{error: "no_default_role"})
  end

  defp handle_create_error(conn, :invalid_role) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_role"})
  end

  defp handle_create_error(conn, :role_escalation) do
    conn |> put_status(:forbidden) |> json(%{error: "role_escalation"})
  end

  defp handle_create_error(conn, :permission_escalation) do
    conn |> put_status(:forbidden) |> json(%{error: "permission_escalation"})
  end

  defp handle_create_error(conn, :permission_denied) do
    conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})
  end

  defp handle_create_error(conn, :not_a_member) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_create_error(conn, :token_hash_already_exists) do
    conn |> put_status(:conflict) |> json(%{error: "token_hash_already_exists"})
  end

  defp handle_create_error(conn, :id_already_exists) do
    conn |> put_status(:conflict) |> json(%{error: "id_already_exists"})
  end

  defp handle_create_error(conn, error) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
  end

  defp handle_accept_error(conn, :not_found) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_accept_error(conn, :invitation_revoked) do
    conn |> put_status(:gone) |> json(%{error: "invitation_revoked"})
  end

  defp handle_accept_error(conn, :invitation_expired) do
    conn |> put_status(:gone) |> json(%{error: "invitation_expired"})
  end

  defp handle_accept_error(conn, :invitation_already_used) do
    conn |> put_status(:gone) |> json(%{error: "invitation_already_used"})
  end

  defp handle_accept_error(conn, :email_mismatch) do
    conn |> put_status(:forbidden) |> json(%{error: "email_mismatch"})
  end

  defp handle_accept_error(conn, :kek_rotation_in_progress) do
    conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})
  end

  defp handle_accept_error(conn, {:invitation_kek_outdated, workspace_id}) do
    conn
    |> put_status(:gone)
    |> json(%{error: "invitation_kek_outdated", workspace_id: workspace_id})
  end

  defp handle_accept_error(conn, :invitation_role_deleted) do
    conn |> put_status(:gone) |> json(%{error: "invitation_role_deleted"})
  end

  defp handle_accept_error(conn, :invalid_token_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_format"})
  end

  defp handle_accept_error(conn, :invalid_token_length) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_length"})
  end

  defp handle_accept_error(conn, error) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
  end
end
