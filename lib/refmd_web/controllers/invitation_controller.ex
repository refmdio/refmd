defmodule RefMDWeb.InvitationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto.Encoding
  alias RefMD.Encryption
  alias RefMD.Users
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

  def create(conn, params) do
    workspace_id = conn.assigns.workspace_id
    user_id = conn.assigns.current_user_id
    actor_role = conn.assigns.workspace_role

    with {:ok, validated} <- validate_create_params(params, workspace_id, user_id),
         validated =
           validated
           |> Map.put(:actor_role, actor_role)
           |> Map.put(:actor_device_id, conn.assigns[:pop_device_id]),
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
    request_body: {"Revocation params", "application/json", Schemas.RevokeInvitationRequest},
    responses: [
      no_content: {"Revoked", "application/json", nil},
      bad_request: {"Invalid ID format", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  def delete(conn, %{"invitation_id" => invitation_id} = params) do
    if Regex.match?(@uuid_regex, invitation_id) do
      case require_workspace_key_directory(params) do
        {:ok, key_directory} -> do_delete(conn, invitation_id, key_directory)
        {:error, reason} -> handle_create_error(conn, reason)
      end
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_invitation_id_format"})
    end
  end

  defp do_delete(conn, invitation_id, key_directory) do
    workspace_id = conn.assigns.workspace_id

    key_directory = put_actor_device_id(key_directory, conn.assigns[:pop_device_id])

    case Workspaces.revoke_invitation(
           workspace_id,
           invitation_id,
           conn.assigns.current_user_id,
           key_directory
         ) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      {:error, :invalid_key_directory} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})
    end
  end

  # ── GET /api/invitations/lookup ─────────────────────

  operation(:lookup,
    summary: "Lookup invitation kind",
    parameters: [token: [in: :query, type: :string, required: true]],
    responses: [
      ok: {"Invitation kind", "application/json", Schemas.InvitationLookupResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def lookup(conn, %{"token" => token}) do
    with {:ok, token_bytes} <- decode_token(token),
         {:ok, token_hash} <- compute_token_hash(token_bytes),
         {:ok, invitation} <- Workspaces.lookup_invitation(token_hash) do
      json(conn, serialize_lookup(invitation))
    else
      {:error, reason} -> handle_lookup_error(conn, reason)
    end
  end

  def lookup(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_token"})
  end

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

  def accept(conn, %{"token" => token}) do
    with {:ok, requester_device_id} <- require_pop_device_id(conn),
         {:ok, admission} <- require_acceptance_admission(conn.body_params),
         {:ok, token_bytes} <- decode_token(token),
         {:ok, token_hash} <- compute_token_hash(token_bytes) do
      user_id = conn.assigns.current_user_id
      user = Users.get_user(user_id)

      case Workspaces.accept_invitation(
             token_hash,
             user_id,
             user.email,
             requester_device_id,
             admission
           ) do
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

  @create_request_keys ~w(
    bootstrap_key_commitment
    bootstrap_package_hash
    bootstrap_package_key_maintenance_wrap
    bootstrap_package_key_recipient_wrap
    bootstrap_suite_id
    capability_context_hash
    encrypted_bootstrap_package
    expires_at
    invitation_id
    invited_email
    kek_version
    role_id
    token_hash
    token_prefix
    workspace_key_directory_checkpoint
    workspace_key_directory_events
  )

  defp validate_create_params(params, workspace_id, user_id) do
    body_params = Map.drop(params, ["workspace_id"])

    with :ok <-
           validate_exact_keys(body_params, @create_request_keys, :unexpected_invitation_keys),
         :ok <- validate_token_hash(body_params["token_hash"]),
         :ok <- validate_token_prefix(body_params["token_prefix"]),
         :ok <- validate_invitation_id(body_params["invitation_id"]),
         :ok <- validate_role_id(workspace_id, body_params["role_id"]),
         :ok <- validate_email(body_params["invited_email"]),
         :ok <- validate_expires_at(body_params["expires_at"]),
         :ok <- validate_commitment(body_params["bootstrap_key_commitment"]),
         :ok <-
           validate_hash(body_params["bootstrap_package_hash"], :invalid_bootstrap_package_hash),
         :ok <-
           validate_map(
             body_params["bootstrap_package_key_recipient_wrap"],
             :invalid_bootstrap_package_key_recipient_wrap
           ),
         :ok <-
           validate_map(
             body_params["bootstrap_package_key_maintenance_wrap"],
             :invalid_bootstrap_package_key_maintenance_wrap
           ),
         :ok <- validate_bootstrap_suite_id(body_params["bootstrap_suite_id"]),
         :ok <-
           validate_hash(body_params["capability_context_hash"], :invalid_capability_context_hash),
         :ok <-
           Workspaces.validate_invitation_encrypted_bootstrap_package(
             body_params["encrypted_bootstrap_package"],
             workspace_id,
             body_params["kek_version"]
           ),
         {:ok, key_directory} <- require_workspace_key_directory(body_params) do
      {:ok,
       %{
         workspace_id: workspace_id,
         invitation_id: body_params["invitation_id"],
         token_hash: body_params["token_hash"],
         token_prefix: body_params["token_prefix"],
         kek_version: body_params["kek_version"],
         role_id: body_params["role_id"],
         invited_by: user_id,
         invited_email: body_params["invited_email"],
         expires_at: parse_expires_at(body_params["expires_at"]),
         bootstrap_key_commitment: body_params["bootstrap_key_commitment"],
         encrypted_bootstrap_package: body_params["encrypted_bootstrap_package"],
         bootstrap_package_hash: body_params["bootstrap_package_hash"],
         bootstrap_package_key_recipient_wrap:
           body_params["bootstrap_package_key_recipient_wrap"],
         bootstrap_package_key_maintenance_wrap:
           body_params["bootstrap_package_key_maintenance_wrap"],
         bootstrap_suite_id: body_params["bootstrap_suite_id"],
         capability_context_hash: body_params["capability_context_hash"],
         key_directory: key_directory
       }}
    end
  end

  defp require_workspace_key_directory(params) do
    events = params["workspace_key_directory_events"]

    checkpoint = params["workspace_key_directory_checkpoint"]

    cond do
      is_nil(events) and is_nil(checkpoint) ->
        {:error, :missing_key_directory}

      is_list(events) and is_map(checkpoint) ->
        {:ok, %{events: events, checkpoint: checkpoint}}

      true ->
        {:error, :invalid_key_directory}
    end
  end

  defp validate_exact_keys(params, keys, reason) when is_map(params) do
    extras = Map.keys(params) -- keys
    if extras == [], do: :ok, else: {:error, reason}
  end

  defp require_acceptance_admission(params) do
    with {:ok, key_directory} <- require_workspace_key_directory(params),
         member_envelope when is_map(member_envelope) <- params["member_envelope"] do
      {:ok, %{key_directory: key_directory, member_envelope: member_envelope}}
    else
      _ -> {:error, :missing_key_directory}
    end
  end

  defp put_actor_device_id(key_directory, actor_device_id),
    do: Map.put(key_directory, :actor_device_id, actor_device_id)

  defp require_pop_device_id(%{assigns: %{pop_device_id: device_id}}) when is_binary(device_id),
    do: {:ok, device_id}

  defp require_pop_device_id(_conn), do: {:error, :missing_device}

  defp validate_token_hash(nil), do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) when not is_binary(hash),
    do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, hash) do
      Encoding.decode_base64url!(hash, 32)
      :ok
    else
      {:error, :invalid_token_hash_format}
    end
  rescue
    ArgumentError -> {:error, :invalid_token_hash_format}
  end

  defp validate_commitment(value) when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value),
      do: :ok,
      else: {:error, :invalid_bootstrap_key_commitment}
  end

  defp validate_commitment(_), do: {:error, :invalid_bootstrap_key_commitment}

  defp validate_hash(value, reason) when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value), do: :ok, else: {:error, reason}
  end

  defp validate_hash(_value, reason), do: {:error, reason}

  defp validate_map(value, _reason) when is_map(value), do: :ok
  defp validate_map(_value, reason), do: {:error, reason}

  defp validate_bootstrap_suite_id("refmd-v2-invitation-bootstrap-xchacha20poly1305"), do: :ok
  defp validate_bootstrap_suite_id(_), do: {:error, :invalid_bootstrap_suite_id}

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

  defp validate_role_id(_workspace_id, nil), do: :ok

  defp validate_role_id(workspace_id, role_id) when is_binary(role_id) do
    cond do
      not Regex.match?(@uuid_regex, role_id) ->
        {:error, :invalid_role}

      match?(%{base_role: "guest"}, Workspaces.get_role_with_permissions(workspace_id, role_id)) ->
        {:error, :invalid_role}

      true ->
        :ok
    end
  end

  defp validate_role_id(_workspace_id, _role_id), do: {:error, :invalid_role}

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
    bytes = Encoding.decode_base64url!(token)
    if byte_size(bytes) == 32, do: {:ok, bytes}, else: {:error, :invalid_token_length}
  rescue
    ArgumentError -> {:error, :invalid_token_format}
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

  defp serialize_lookup(%RefMD.Workspaces.WorkspaceInvitation{} = invitation) do
    current_checkpoint =
      Encryption.current_workspace_key_directory_checkpoint(invitation.workspace_id)

    ancestry =
      invitation_lookup_ancestry(
        invitation.workspace_id,
        "workspace_invitation_created",
        "invitation_id",
        invitation.id,
        current_checkpoint
      )

    %{
      kind: "workspace",
      invitation_id: invitation.id,
      kek_version: invitation.kek_version,
      encrypted_bootstrap_package: invitation.encrypted_bootstrap_package,
      workspace_key_directory_checkpoint: serialize_checkpoint(current_checkpoint),
      workspace_key_directory_checkpoint_ancestry: ancestry.checkpoints,
      workspace_key_directory_event_ancestry: ancestry.events
    }
  end

  defp serialize_lookup(%RefMD.Workspaces.GuestInvitation{} = invitation) do
    {scope_kind, scope_id} =
      case invitation.scope_kind do
        "workspace" -> {"workspace", "none"}
        scope -> {scope, invitation.scope_id}
      end

    current_checkpoint =
      Encryption.current_workspace_key_directory_checkpoint(invitation.workspace_id)

    ancestry =
      invitation_lookup_ancestry(
        invitation.workspace_id,
        "guest_invitation_created",
        "guest_invitation_id",
        invitation.id,
        current_checkpoint
      )

    %{
      kind: "guest",
      invitation_id: invitation.id,
      workspace_id: invitation.workspace_id,
      scope_kind: scope_kind,
      scope_id: scope_id,
      permission: invitation.permission,
      kek_version: invitation.kek_version,
      encrypted_bootstrap_package: invitation.encrypted_bootstrap_package,
      workspace_key_directory_checkpoint: serialize_checkpoint(current_checkpoint),
      workspace_key_directory_checkpoint_ancestry: ancestry.checkpoints,
      workspace_key_directory_event_ancestry: ancestry.events
    }
  end

  defp invitation_lookup_ancestry(
         workspace_id,
         created_event_type,
         invitation_body_key,
         invitation_id,
         current_checkpoint
       ) do
    ancestry =
      Workspaces.invitation_lookup_ancestry(
        workspace_id,
        created_event_type,
        invitation_body_key,
        invitation_id,
        current_checkpoint
      )

    %{
      checkpoints: Enum.map(ancestry.checkpoints, &serialize_checkpoint/1),
      events: Enum.map(ancestry.events, &serialize_event/1)
    }
  end

  defp serialize_checkpoint(nil), do: nil

  defp serialize_checkpoint(checkpoint) do
    %{payload: checkpoint.payload, signatures: checkpoint.signatures}
  end

  defp serialize_event(event) do
    %{payload: event.payload, signatures: event.signatures}
  end

  defp serialize_acceptance(result) do
    %{
      status: result[:status] || "accepted",
      workspace_id: result.workspace_id,
      workspace_name: result.workspace_name,
      role_name: result.role_name,
      invitation_id: result.invitation_id,
      kek_version: result.kek_version,
      encrypted_bootstrap_package: result[:encrypted_bootstrap_package],
      workspace_key_directory_checkpoint: result[:workspace_key_directory_checkpoint]
    }
  end

  defp handle_create_error(conn, :invalid_token_hash_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_hash_format"})
  end

  defp handle_create_error(conn, :unexpected_invitation_keys) do
    conn |> put_status(:bad_request) |> json(%{error: "unexpected_invitation_keys"})
  end

  defp handle_create_error(conn, :invalid_token_prefix) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_prefix"})
  end

  defp handle_create_error(conn, :invalid_encrypted_bootstrap_package) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_encrypted_bootstrap_package"})
  end

  defp handle_create_error(conn, :invalid_bootstrap_package_key_recipient_wrap) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_bootstrap_package_key_recipient_wrap"})
  end

  defp handle_create_error(conn, :invalid_bootstrap_package_key_maintenance_wrap) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_bootstrap_package_key_maintenance_wrap"})
  end

  defp handle_create_error(conn, :invalid_bootstrap_key_commitment) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_bootstrap_key_commitment"})
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

  defp handle_create_error(conn, :invalid_key_directory) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})
  end

  defp handle_create_error(conn, :missing_key_directory) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})
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

  defp handle_accept_error(conn, :missing_device) do
    conn |> put_status(:forbidden) |> json(%{error: "missing_device"})
  end

  defp handle_accept_error(conn, :invalid_key_directory) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})
  end

  defp handle_accept_error(conn, :missing_key_directory) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})
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

  defp handle_lookup_error(conn, :not_found) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_lookup_error(conn, :invalid_token_format) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_format"})
  end

  defp handle_lookup_error(conn, :invalid_token_length) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_length"})
  end
end
