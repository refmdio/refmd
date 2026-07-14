defmodule RefMDWeb.InvitationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto.{Encoding, Hash, JCS}
  alias RefMD.Encryption
  alias RefMD.Users
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug RequireRBAC,
       [permission: "member:invite", not_member_status: :not_found]
       when action in [
              :index,
              :create,
              :delete,
              :resolve_recipient
            ]

  # Accept uses no workspace RBAC (email-bound, RRP required)

  @max_expires_days 30

  operation(:resolve_recipient,
    summary: "Resolve a workspace invitation recipient",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      email: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Recipient delivery", "application/json", Schemas.InvitationRecipientResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Recipient unavailable", "application/json", Schemas.ErrorResponse}
    ]
  )

  def resolve_recipient(conn, %{"email" => email}) when is_binary(email) do
    if String.match?(email, ~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/) do
      case Users.resolve_invitation_recipient(email) do
        {:ok, recipient} -> json(conn, recipient)
        {:error, :recipient_delivery_unavailable} -> recipient_delivery_unavailable(conn)
      end
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_email"})
    end
  end

  def resolve_recipient(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_email"})
  end

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
           |> Map.put(:actor_device_id, conn.assigns[:rrp_device_id]),
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

    key_directory = put_actor_device_id(key_directory, conn.assigns[:rrp_device_id])

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
    with {:ok, requester_device_id} <- require_rrp_device_id(conn),
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

  operation(:create_delivery_attempt,
    summary: "Create a known-recipient invitation delivery attempt",
    request_body:
      {"Delivery attempt", "application/json", Schemas.CreateInvitationDeliveryAttemptRequest},
    responses: [
      created:
        {"Created delivery attempt", "application/json",
         Schemas.InvitationDeliveryAttemptResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_delivery_attempt(conn, %{"token" => token} = params) do
    with {:ok, recipient_device_id} <- require_rrp_device_id(conn),
         {:ok, token_bytes} <- decode_token(token),
         {:ok, token_hash} <- compute_token_hash(token_bytes),
         {:ok, attempt} <-
           Workspaces.create_invitation_delivery_attempt(
             token_hash,
             conn.assigns.current_user_id,
             recipient_device_id,
             Map.delete(params, "token")
           ) do
      conn
      |> put_status(:created)
      |> json(serialize_delivery_attempt(attempt))
    else
      {:error, reason} -> handle_delivery_attempt_error(conn, reason)
    end
  end

  def create_delivery_attempt(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_token"})
  end

  operation(:show_delivery_attempt,
    summary: "Get a known-recipient invitation delivery attempt",
    parameters: [attempt_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Delivery attempt", "application/json", Schemas.InvitationDeliveryAttemptResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_delivery_attempt(conn, %{"attempt_id" => attempt_id}) do
    with {:ok, recipient_device_id} <- require_rrp_device_id(conn),
         {:ok, attempt} <-
           Workspaces.get_invitation_delivery_attempt(
             attempt_id,
             conn.assigns.current_user_id,
             recipient_device_id
           ) do
      json(conn, serialize_delivery_attempt(attempt))
    else
      {:error, reason} -> handle_delivery_attempt_error(conn, reason)
    end
  end

  operation(:delivery_attempts,
    summary: "List pending invitation delivery attempts",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok:
        {"Pending delivery attempts", "application/json",
         Schemas.InvitationDeliveryAttemptListResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delivery_attempts(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    can_manage_members =
      Workspaces.member_permission_granted?(workspace_id, user_id, "member:invite")

    can_manage_guests =
      Workspaces.member_permission_granted?(workspace_id, user_id, "guest:invite")

    if can_manage_members or can_manage_guests do
      attempts =
        workspace_id
        |> Workspaces.list_pending_invitation_delivery_attempts()
        |> Enum.filter(fn attempt ->
          (attempt.context_kind == "workspace_invitation" and can_manage_members) or
            (attempt.context_kind == "guest_invitation" and can_manage_guests)
        end)
        |> Enum.map(&serialize_delivery_attempt/1)

      json(conn, %{attempts: attempts})
    else
      conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:approve_delivery_attempt,
    summary: "Approve a known-recipient invitation delivery attempt",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      attempt_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Delivery approval", "application/json", Schemas.ApproveInvitationDeliveryAttemptRequest},
    responses: [
      ok:
        {"Approved delivery attempt", "application/json",
         Schemas.InvitationDeliveryAttemptResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def approve_delivery_attempt(conn, %{
        "workspace_id" => workspace_id,
        "attempt_id" => attempt_id
      }) do
    with {:ok, actor_device_id} <- require_rrp_device_id(conn),
         {:ok, attempt} <-
           Workspaces.approve_invitation_delivery_attempt(
             workspace_id,
             attempt_id,
             conn.assigns.current_user_id,
             actor_device_id,
             conn.body_params
           ) do
      json(conn, serialize_delivery_attempt(attempt))
    else
      {:error, reason} -> handle_delivery_attempt_error(conn, reason)
    end
  end

  operation(:consume_delivery_attempt,
    summary: "Consume an approved workspace invitation delivery attempt",
    parameters: [attempt_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Delivery consume", "application/json", Schemas.ConsumeInvitationDeliveryAttemptRequest},
    responses: [
      ok: {"Accepted", "application/json", Schemas.AcceptInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def consume_delivery_attempt(conn, %{"attempt_id" => attempt_id, "token" => token}) do
    with {:ok, recipient_device_id} <- require_rrp_device_id(conn),
         {:ok, token_bytes} <- decode_token(token),
         {:ok, token_hash} <- compute_token_hash(token_bytes),
         {:ok, result} <-
           Workspaces.consume_workspace_invitation_delivery_attempt(
             attempt_id,
             token_hash,
             conn.assigns.current_user_id,
             recipient_device_id
           ) do
      json(conn, serialize_acceptance(result))
    else
      {:error, reason} -> handle_delivery_attempt_error(conn, reason)
    end
  end

  def consume_delivery_attempt(conn, _params) do
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
    delivery_mode
    encrypted_bootstrap_package
    expires_at
    invitation_id
    invited_email
    kek_version
    recipient_device_ids
    recipient_user_id
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
         :ok <-
           validate_delivery_binding(
             body_params["invited_email"],
             body_params["delivery_mode"],
             body_params["recipient_user_id"],
             body_params["recipient_device_ids"]
           ),
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
         :ok <- validate_package_recipient_binding(body_params),
         :ok <- validate_bootstrap_request_binding(body_params),
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
         delivery_mode: body_params["delivery_mode"],
         recipient_user_id: body_params["recipient_user_id"],
         recipient_device_ids: body_params["recipient_device_ids"],
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

  defp require_rrp_device_id(%{assigns: %{rrp_device_id: device_id}}) when is_binary(device_id),
    do: {:ok, device_id}

  defp require_rrp_device_id(_conn), do: {:error, :missing_device}

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

  defp validate_delivery_binding(email, mode, recipient_user_id, recipient_device_ids) do
    Users.validate_invitation_delivery_binding(
      email,
      mode,
      recipient_user_id,
      recipient_device_ids
    )
  end

  defp validate_package_recipient_binding(%{"delivery_mode" => "unknown_fragment"} = params) do
    package_wrap = get_in(params, ["encrypted_bootstrap_package", "package_key_recipient_wrap"])
    request_wrap = params["bootstrap_package_key_recipient_wrap"]

    case package_wrap do
      %{"nonce" => _, "ciphertext" => _} ->
        if package_wrap == request_wrap,
          do: :ok,
          else: {:error, :recipient_delivery_mismatch}

      _ ->
        {:error, :recipient_delivery_mismatch}
    end
  end

  defp validate_package_recipient_binding(%{"delivery_mode" => "known_recipient"} = params) do
    wrap = get_in(params, ["encrypted_bootstrap_package", "package_key_recipient_wrap"])

    if wrap == params["bootstrap_package_key_recipient_wrap"] and
         wrap["recipient_user_id"] == params["recipient_user_id"] and
         wrap["wraps"] == [],
       do: :ok,
       else: {:error, :recipient_delivery_mismatch}
  end

  defp validate_package_recipient_binding(_), do: {:error, :recipient_delivery_mismatch}

  defp validate_bootstrap_request_binding(params) do
    package = params["encrypted_bootstrap_package"]
    aad = package["aad"]
    expected_recipient_user_id = params["recipient_user_id"] || "NOT_APPLICABLE"

    if Enum.all?([
         aad["invitation_id"] == params["invitation_id"],
         aad["role_id"] == params["role_id"],
         aad["invited_email"] == String.downcase(params["invited_email"]),
         aad["token_hash"] == params["token_hash"],
         aad["delivery_mode"] == params["delivery_mode"],
         aad["recipient_user_id"] == expected_recipient_user_id,
         Enum.sort(aad["recipient_device_ids"] || []) ==
           Enum.sort(params["recipient_device_ids"] || []),
         Hash.blake3_base64url(JCS.canonical_bytes!(package)) ==
           params["bootstrap_package_hash"]
       ]),
       do: :ok,
       else: {:error, :invalid_encrypted_bootstrap_package}
  rescue
    _ -> {:error, :invalid_encrypted_bootstrap_package}
  end

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
      delivery_mode: invitation.delivery_mode,
      recipient_user_id: invitation.recipient_user_id,
      recipient_device_ids: invitation.recipient_device_ids,
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
      delivery_mode: invitation.delivery_mode,
      recipient_user_id: invitation.recipient_user_id,
      recipient_device_ids: invitation.recipient_device_ids,
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
      share_id: invitation.share_id,
      permission: invitation.permission,
      delivery_mode: invitation.delivery_mode,
      recipient_user_id: invitation.recipient_user_id,
      recipient_device_ids: invitation.recipient_device_ids,
      kek_version: invitation.kek_version,
      key_version_context: guest_invitation_key_version_context(invitation),
      encrypted_bootstrap_package: invitation.encrypted_bootstrap_package,
      workspace_key_directory_checkpoint: serialize_checkpoint(current_checkpoint),
      workspace_key_directory_checkpoint_ancestry: ancestry.checkpoints,
      workspace_key_directory_event_ancestry: ancestry.events
    }
  end

  defp guest_invitation_key_version_context(%{scope_kind: "workspace"} = invitation) do
    %{
      workspace_kek_version: invitation.kek_version,
      share_key_version: "NOT_APPLICABLE",
      dek_version: "NOT_APPLICABLE"
    }
  end

  defp guest_invitation_key_version_context(invitation) do
    %{
      workspace_kek_version: "NOT_APPLICABLE",
      share_key_version: invitation.share_key_version,
      dek_version: invitation.dek_version
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
      workspace_key_directory_checkpoint: result[:workspace_key_directory_checkpoint],
      recipient_delivery_artifacts: result[:recipient_delivery_artifacts]
    }
  end

  defp serialize_delivery_attempt(attempt) do
    %{
      redeem_attempt_id: attempt.id,
      workspace_id: attempt.workspace_id,
      context_kind: attempt.context_kind,
      context_id: attempt.context_id,
      recipient_user_id: attempt.recipient_user_id,
      recipient_device_id: attempt.recipient_device_id,
      target_user_id: attempt.target_user_id,
      target_device_id: attempt.target_device_id,
      target_encryption_key_id: attempt.target_encryption_key_id,
      target_key_checkpoint_sequence: attempt.target_key_checkpoint_sequence,
      target_key_checkpoint_hash: attempt.target_key_checkpoint_hash,
      target_registration: attempt.target_registration,
      target_registration_proof: attempt.target_registration_proof,
      recipient_redeem_nonce: attempt.recipient_redeem_nonce,
      live_redeem_challenge_hash: attempt.live_redeem_challenge_hash,
      recipient_nonce_state_hash: attempt.recipient_nonce_state_hash,
      request_binding_hash: attempt.request_binding_hash,
      resource_hash: attempt.resource_hash,
      context_snapshot: attempt.context_snapshot,
      status: attempt.status,
      authorization_id: attempt.authorization_id,
      approved_artifacts: attempt.approved_artifacts,
      expires_at: attempt.expires_at,
      created_at: attempt.created_at
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

  defp handle_create_error(conn, :recipient_delivery_mismatch) do
    conn |> put_status(:conflict) |> json(%{error: "recipient_delivery_mismatch"})
  end

  defp handle_create_error(conn, :recipient_delivery_unavailable),
    do: recipient_delivery_unavailable(conn)

  defp handle_create_error(conn, :recipient_already_member) do
    conn |> put_status(:conflict) |> json(%{error: "recipient_already_member"})
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

  defp recipient_delivery_unavailable(conn) do
    conn |> put_status(:conflict) |> json(%{error: "recipient_delivery_unavailable"})
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

  defp handle_accept_error(conn, :recipient_mismatch) do
    conn |> put_status(:forbidden) |> json(%{error: "recipient_mismatch"})
  end

  defp handle_accept_error(conn, :recipient_device_mismatch) do
    conn |> put_status(:forbidden) |> json(%{error: "recipient_device_mismatch"})
  end

  defp handle_accept_error(conn, :recipient_device_revoked) do
    conn |> put_status(:gone) |> json(%{error: "recipient_device_revoked"})
  end

  defp handle_accept_error(conn, :recipient_delivery_required) do
    conn |> put_status(:conflict) |> json(%{error: "recipient_delivery_required"})
  end

  defp handle_accept_error(conn, :recipient_already_member) do
    conn |> put_status(:conflict) |> json(%{error: "recipient_already_member"})
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

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [:not_found, :recipient_delivery_not_required] do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [:delivery_attempt_not_pending, :delivery_attempt_expired] do
    conn |> put_status(:conflict) |> json(%{error: to_string(reason)})
  end

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [
              :delivery_attempt_not_approved,
              :delivery_attempt_token_mismatch,
              :delivery_approval_stale
            ] do
    conn |> put_status(:conflict) |> json(%{error: to_string(reason)})
  end

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [:permission_denied, :approver_device_invalid] do
    conn |> put_status(:forbidden) |> json(%{error: to_string(reason)})
  end

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [
              :recipient_mismatch,
              :recipient_device_mismatch,
              :recipient_target_mismatch,
              :recipient_target_key_mismatch
            ] do
    conn |> put_status(:forbidden) |> json(%{error: to_string(reason)})
  end

  defp handle_delivery_attempt_error(conn, reason)
       when reason in [
              :recipient_device_revoked,
              :invitation_revoked,
              :invitation_expired,
              :invitation_used,
              :invitation_redemptions_exhausted
            ] do
    conn |> put_status(:gone) |> json(%{error: to_string(reason)})
  end

  defp handle_delivery_attempt_error(conn, :missing_device) do
    conn |> put_status(:forbidden) |> json(%{error: "missing_device"})
  end

  defp handle_delivery_attempt_error(conn, reason) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
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
