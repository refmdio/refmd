defmodule RefMDWeb.RoleController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug :validate_role_id when action in [:update, :delete]

  plug RequireRBAC, [permission: :membership] when action in [:index]
  plug RequireRBAC, [permission: "role:manage"] when action in [:create, :update, :delete]

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  defp validate_role_id(conn, _opts) do
    role_id = conn.path_params["role_id"]

    if is_binary(role_id) and Regex.match?(@uuid_regex, role_id) do
      conn
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "invalid_role_id"})
      |> halt()
    end
  end

  # ── GET /api/workspaces/:workspace_id/roles ───────────

  operation(:index,
    summary: "List workspace roles",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Role list", "application/json", Schemas.RolesListResponse}
    ]
  )

  def index(conn, _params) do
    roles = Workspaces.list_workspace_roles(conn.assigns.workspace_id)
    json(conn, %{roles: Enum.map(roles, &serialize_role/1)})
  end

  # ── POST /api/workspaces/:workspace_id/roles ──────────

  operation(:create,
    summary: "Create a custom role",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body: {"Role params", "application/json", Schemas.CreateRoleRequest},
    responses: [
      created: {"Created role", "application/json", Schemas.RoleResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create(conn, %{"name" => name, "base_role" => base_role} = params) do
    workspace_id = conn.assigns.workspace_id
    permissions = params["permissions"]

    create_role_with_permissions(conn, workspace_id, name, base_role, permissions)
  end

  def create(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_required_fields"})
  end

  # ── PATCH /api/workspaces/:workspace_id/roles/:role_id

  operation(:update,
    summary: "Update a role",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      role_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Update params", "application/json", Schemas.UpdateRoleRequest},
    responses: [
      ok: {"Updated role", "application/json", Schemas.RoleResponse},
      bad_request: {"Invalid permission", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update(conn, %{"role_id" => role_id} = params) do
    workspace_id = conn.assigns.workspace_id

    case Workspaces.get_role_with_permissions(workspace_id, role_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "role_not_found"})

      role ->
        update_role(conn, role, params)
    end
  end

  # ── DELETE /api/workspaces/:workspace_id/roles/:role_id

  operation(:delete,
    summary: "Delete a custom role",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      role_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Deleted", "application/json", Schemas.RoleDeleteResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Cannot delete", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete(conn, %{"role_id" => role_id}) do
    workspace_id = conn.assigns.workspace_id

    case Workspaces.get_role_with_permissions(workspace_id, role_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "role_not_found"})

      %{catalog_version: nil} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "builtin_role_immutable"})

      %{is_default: true} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "cannot_delete_default_role"})

      role ->
        case Workspaces.delete_role(role) do
          {:ok, count} ->
            json(conn, %{ok: true, invalidated_invitation_count: count})

          {:error, :cannot_delete_default_role} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "cannot_delete_default_role"})

          {:error, :role_in_use} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "role_in_use"})
        end
    end
  end

  # ── Helpers ───────────────────────────────────────────

  defp create_role_with_permissions(conn, workspace_id, name, base_role, permissions) do
    case Workspaces.create_custom_role(workspace_id, name, base_role, permissions,
           actor_role: conn.assigns.workspace_role
         ) do
      {:ok, role} ->
        conn |> put_status(:created) |> json(serialize_role(role))

      {:error, error} ->
        handle_role_error(conn, error)
    end
  end

  defp update_role(conn, role, params) do
    cond do
      Map.has_key?(params, "base_role") ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "base_role_immutable"})

      role.catalog_version == nil and has_non_default_changes?(params) ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "builtin_role_immutable"})

      Map.has_key?(params, "is_default") and
        params["is_default"] != role.is_default and
          conn.assigns.workspace_role.base_role != "owner" ->
        conn |> put_status(:forbidden) |> json(%{error: "owner_only_operation"})

      true ->
        apply_role_update(conn, role, params)
    end
  end

  defp has_non_default_changes?(params) do
    Map.has_key?(params, "name") or Map.has_key?(params, "permissions")
  end

  defp apply_role_update(conn, role, params) do
    permissions = params["permissions"]
    name = params["name"]
    is_default = params["is_default"]

    case Workspaces.update_role(role, %{name: name, is_default: is_default},
           permissions: permissions,
           actor_role: conn.assigns.workspace_role
         ) do
      {:ok, updated_role} ->
        json(conn, serialize_role(updated_role))

      {:error, error} ->
        handle_role_error(conn, error)
    end
  end

  defp handle_role_error(conn, :owner_role_not_allowed) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "owner_role_not_allowed"})
  end

  defp handle_role_error(conn, :invalid_base_role) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_base_role"})
  end

  defp handle_role_error(conn, {:invalid_permission, perm}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_permission", permission: perm})
  end

  defp handle_role_error(conn, {:permission_exceeds_base_role, perm}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "permission_exceeds_base_role", permission: perm})
  end

  defp handle_role_error(conn, {:permission_exceeds_actor, perm}) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "permission_exceeds_actor", permission: perm})
  end

  defp handle_role_error(conn, :actor_not_member) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "actor_not_member"})
  end

  defp handle_role_error(conn, {:invalid_permission_dependency, perm}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "invalid_permission_dependency", permission: perm})
  end

  defp handle_role_error(conn, :cannot_unset_default_role) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "cannot_unset_default_role"})
  end

  defp handle_role_error(conn, :guest_role_default_not_allowed) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "guest_role_default_not_allowed"})
  end

  defp handle_role_error(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_error", details: format_errors(changeset)})
  end

  defp serialize_role(role) do
    permissions =
      case role.permissions do
        %Ecto.Association.NotLoaded{} -> []
        perms -> Enum.map(perms, &%{permission: &1.permission, granted: &1.granted})
      end

    %{
      id: role.id,
      workspace_id: role.workspace_id,
      name: role.name,
      base_role: role.base_role,
      is_default: role.is_default,
      catalog_version: role.catalog_version,
      created_at: role.created_at,
      permissions: permissions
    }
  end
end
