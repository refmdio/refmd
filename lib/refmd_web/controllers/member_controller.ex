defmodule RefMDWeb.MemberController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Encryption, Workspaces}
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug :validate_user_id when action in [:devices, :update, :delete]
  plug :allow_guest_crypto_access when action in [:identity_keys, :devices]

  plug RequireRBAC, [permission: "member:list"] when action in [:index]
  plug RequireRBAC, [permission: :membership] when action in [:identity_keys, :devices]
  plug RequireRBAC, [permission: "member:change_role"] when action in [:update]

  # DELETE uses manual RBAC check for self-removal bypass
  plug RequireRBAC, [permission: :membership] when action in [:delete]

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  defp allow_guest_crypto_access(conn, _opts) do
    assign(conn, :allow_guest_crypto_access, true)
  end

  defp validate_user_id(conn, _opts) do
    user_id = conn.path_params["user_id"]

    if is_binary(user_id) and Regex.match?(@uuid_regex, user_id) do
      conn
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "invalid_user_id"})
      |> halt()
    end
  end

  # ── GET /api/workspaces/:workspace_id/members ─────────

  operation(:index,
    summary: "List workspace members",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Member list", "application/json", Schemas.MembersListResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def index(conn, _params) do
    members = Workspaces.list_workspace_members(conn.assigns.workspace_id)
    json(conn, %{members: members})
  end

  # ── GET /api/workspaces/:workspace_id/members/:user_id/devices

  operation(:devices,
    summary: "List a member's devices",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      user_id: [in: :path, type: :string, required: true],
      include_revoked: [in: :query, type: :boolean, required: false]
    ],
    responses: [
      ok: {"Member devices", "application/json", Schemas.MemberDevicesResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def devices(conn, params) do
    target_user_id = params["user_id"]
    workspace_id = conn.assigns.workspace_id
    include_revoked = params["include_revoked"] == "true"

    if Workspaces.get_workspace_member(workspace_id, target_user_id) do
      devices = Devices.get_user_devices(target_user_id, include_revoked: include_revoked)

      json(conn, %{
        devices:
          Enum.map(devices, fn d ->
            %{
              device_id: d.id,
              hybrid_signing_public_key_material: d.hybrid_signing_public_key_material,
              signing_key_id: d.signing_key_id,
              hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
              encryption_key_id: d.encryption_key_id,
              approval_signature: d.approval_signature,
              approval_signature_surface: d.approval_signature_surface,
              approval_proof: d.approval_proof,
              approval_delivery_commitments: d.approval_delivery_commitments,
              client_nonce: Base.url_encode64(d.client_nonce, padding: false),
              revoked_at: d.revoked_at,
              created_at: d.created_at
            }
          end)
      })
    else
      conn |> put_status(:not_found) |> json(%{error: "member_not_found"})
    end
  end

  # ── PATCH /api/workspaces/:workspace_id/members/:user_id

  operation(:update,
    summary: "Change a member's role",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      user_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Role change", "application/json", Schemas.ChangeMemberRoleRequest},
    responses: [
      ok: {"Updated member", "application/json", Schemas.ChangeMemberRoleResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update(conn, %{"user_id" => target_user_id, "role_id" => new_role_id}) do
    workspace_id = conn.assigns.workspace_id
    actor_user_id = conn.assigns.current_user_id

    case Workspaces.change_member_role(
           workspace_id,
           target_user_id,
           new_role_id,
           actor_user_id,
           %{
             workspace_events: conn.body_params["workspace_key_directory_events"],
             workspace_checkpoint: conn.body_params["workspace_key_directory_checkpoint"]
           }
         ) do
      {:ok, _member} ->
        json(conn, %{
          ok: true,
          workspaces_needing_kek_rotation: workspace_rotation_info(workspace_id)
        })

      {:error, error} ->
        handle_member_error(conn, error)
    end
  end

  def update(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_role_id"})
  end

  # ── DELETE /api/workspaces/:workspace_id/members/:user_id

  operation(:delete,
    summary: "Remove a member or leave workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      user_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Remove member params", "application/json", Schemas.RemoveMemberRequest},
    responses: [
      ok: {"Removed", "application/json", Schemas.RemoveMemberResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Last owner", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete(conn, %{"user_id" => target_user_id} = params) do
    workspace_id = conn.assigns.workspace_id
    actor_user_id = conn.assigns.current_user_id

    cond do
      # Self-removal: RRP required, RBAC bypassed
      target_user_id == actor_user_id ->
        do_remove(conn, workspace_id, target_user_id, actor_user_id, params)

      # Other removal: requires member:remove permission
      has_permission?(conn.assigns.workspace_role, "member:remove") ->
        do_remove(conn, workspace_id, target_user_id, actor_user_id, params)

      true ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  # ── GET /api/workspaces/:workspace_id/member-keys ────

  operation(:identity_keys,
    summary: "Get Identity ECDH public keys for all workspace members",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Member keys", "application/json", Schemas.WorkspaceMemberKeysResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def identity_keys(conn, _params) do
    members =
      conn.assigns.workspace_id
      |> Workspaces.list_workspace_members()
      |> Enum.reject(&(&1.base_role == "guest"))

    json(conn, %{
      members:
        Enum.map(members, fn member ->
          identity =
            case Encryption.user_identity_key_for_new_encryption(member.user_id) do
              {:ok, key} -> key
              {:error, _reason} -> nil
            end

          %{
            user_id: member.user_id,
            hybrid_encryption_public_key_material:
              identity && identity.hybrid_encryption_public_key_material,
            hybrid_signing_public_key_material:
              identity && identity.hybrid_signing_public_key_material
          }
        end)
        |> Enum.reject(&is_nil(&1.hybrid_encryption_public_key_material))
    })
  end

  defp do_remove(conn, workspace_id, target_user_id, actor_user_id, params) do
    case Workspaces.remove_member(workspace_id, target_user_id, actor_user_id, %{
           workspace_events: params["workspace_key_directory_events"],
           workspace_checkpoint: params["workspace_key_directory_checkpoint"]
         }) do
      {:ok, _member} ->
        json(conn, %{
          ok: true,
          workspaces_needing_kek_rotation: workspace_rotation_info(workspace_id)
        })

      {:error, error} ->
        handle_member_error(conn, error)
    end
  end

  defp has_permission?(role, permission) do
    perms = Workspaces.effective_permissions(role)
    MapSet.member?(perms, permission)
  end

  defp workspace_rotation_info(workspace_id) do
    case Workspaces.get_workspace(workspace_id) do
      %{needs_kek_rotation: true, current_kek_version: version} ->
        [%{workspace_id: workspace_id, current_kek_version: version}]

      _ ->
        []
    end
  end

  defp handle_member_error(conn, :cannot_modify_owner) do
    conn |> put_status(:forbidden) |> json(%{error: "cannot_modify_owner"})
  end

  defp handle_member_error(conn, :role_escalation) do
    conn |> put_status(:forbidden) |> json(%{error: "role_escalation"})
  end

  defp handle_member_error(conn, :permission_escalation) do
    conn |> put_status(:forbidden) |> json(%{error: "permission_escalation"})
  end

  defp handle_member_error(conn, :permission_denied) do
    conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})
  end

  defp handle_member_error(conn, :last_owner) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "last_owner"})
  end

  defp handle_member_error(conn, :target_not_member) do
    conn |> put_status(:not_found) |> json(%{error: "member_not_found"})
  end

  defp handle_member_error(conn, :actor_not_member) do
    conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
  end

  defp handle_member_error(conn, :invalid_role) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_role"})
  end

  defp handle_member_error(conn, :guest_role_immutable) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "guest_role_immutable"})
  end

  defp handle_member_error(conn, error) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
  end
end
