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

  # ── Permission dependency rules ───────────────────────

  @permission_dependencies [
    {"document:write", "document:read"},
    {"document:read", "member:list"}
  ]

  # ── GET /api/workspaces/:workspace_id/roles ───────────

  operation(:index,
    summary: "List workspace roles",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Role list", "application/json", Schemas.RolesListResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{"name" => name, "base_role" => base_role} = params) do
    workspace_id = conn.assigns.workspace_id
    permissions = params["permissions"]

    cond do
      base_role == "owner" ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "owner_role_not_allowed"})

      base_role not in ~w(admin editor viewer) ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_base_role"})

      true ->
        create_role_with_permissions(conn, workspace_id, name, base_role, permissions)
    end
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

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
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

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
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
    case validate_permissions_for_create(permissions, base_role) do
      {:error, error} ->
        handle_permission_error(conn, error)

      {:ok, resolved_permissions} ->
        case Workspaces.create_custom_role(workspace_id, name, base_role, resolved_permissions) do
          {:ok, role} ->
            conn |> put_status(:created) |> json(serialize_role(role))

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "validation_error", details: format_errors(changeset)})
        end
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

    submitted_keys =
      if permissions,
        do: Enum.map(permissions, fn %{"permission" => p} -> p end),
        else: nil

    case validate_permissions_if_present(permissions, role.base_role, role) do
      {:error, error} ->
        handle_permission_error(conn, error)

      {:ok, resolved_permissions} ->
        case Workspaces.update_role(role, %{name: name, is_default: is_default},
               permissions: resolved_permissions,
               submitted_keys: submitted_keys
             ) do
          {:ok, updated_role} ->
            json(conn, serialize_role(updated_role))

          {:error, :cannot_unset_default_role} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "cannot_unset_default_role"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "validation_error", details: format_errors(changeset)})
        end
    end
  end

  defp validate_permissions_for_create(nil, _base_role), do: {:ok, nil}

  defp validate_permissions_for_create(permissions, base_role) do
    catalog = RequireRBAC.permission_catalog()
    power = RequireRBAC.role_power()
    role_power_val = power[base_role]

    with :ok <- validate_permission_keys(permissions, catalog),
         :ok <- validate_permission_ceilings(permissions, catalog, power, role_power_val) do
      case validate_permission_dependencies(permissions, base_role, nil) do
        :ok -> {:ok, filter_default_matching_overrides(permissions, base_role, nil)}
        error -> error
      end
    end
  end

  defp validate_permissions_if_present(nil, _base_role, _role), do: {:ok, nil}

  defp validate_permissions_if_present(permissions, base_role, role) do
    catalog = RequireRBAC.permission_catalog()
    power = RequireRBAC.role_power()
    role_power_val = power[base_role]
    cv = role.catalog_version

    with :ok <- validate_permission_keys(permissions, catalog),
         :ok <- validate_permission_ceilings(permissions, catalog, power, role_power_val) do
      merged = merge_with_existing_overrides(permissions, role)

      case validate_permission_dependencies(merged, base_role, cv) do
        :ok -> {:ok, filter_default_matching_overrides(merged, base_role, cv)}
        error -> error
      end
    end
  end

  defp merge_with_existing_overrides(submitted, role) do
    existing_map =
      Map.new(role.permissions, fn p ->
        {p.permission, %{"permission" => p.permission, "granted" => p.granted}}
      end)

    submitted_map =
      Map.new(submitted, fn %{"permission" => p, "granted" => g} ->
        {p, %{"permission" => p, "granted" => g}}
      end)

    Map.merge(existing_map, submitted_map)
    |> Map.values()
  end

  defp validate_permission_keys(permissions, catalog) do
    invalid =
      Enum.find(permissions, fn entry ->
        not is_map_key(entry, "permission") or not is_map_key(entry, "granted") or
          not is_binary(entry["permission"]) or not is_boolean(entry["granted"]) or
          not Map.has_key?(catalog, entry["permission"])
      end)

    if invalid, do: {:error, {:invalid_permission, invalid["permission"]}}, else: :ok
  end

  defp validate_permission_ceilings(permissions, catalog, power, role_power_val) do
    violation =
      Enum.find(permissions, fn %{"permission" => perm} ->
        power[catalog[perm].base_role_ceiling] > role_power_val
      end)

    if violation,
      do: {:error, {:permission_exceeds_base_role, violation["permission"]}},
      else: :ok
  end

  defp validate_permission_dependencies(permissions, base_role, catalog_version) do
    overrides = Map.new(permissions, fn %{"permission" => p, "granted" => g} -> {p, g} end)

    resolved = fn perm ->
      case Map.get(overrides, perm) do
        nil -> effective_default?(perm, base_role, catalog_version)
        val -> val
      end
    end

    violation =
      Enum.find(@permission_dependencies, fn {requires, required_by} ->
        resolved.(requires) and not resolved.(required_by)
      end)

    if violation do
      {requires, _} = violation
      {:error, {:invalid_permission_dependency, requires}}
    else
      :ok
    end
  end

  defp filter_default_matching_overrides(permissions, base_role, catalog_version) do
    Enum.filter(permissions, fn %{"permission" => perm, "granted" => granted} ->
      granted != effective_default?(perm, base_role, catalog_version)
    end)
  end

  defp effective_default?(perm, base_role, catalog_version) do
    catalog = RequireRBAC.permission_catalog()
    defaults = RequireRBAC.base_role_defaults()[base_role]

    if catalog_version != nil and catalog[perm] != nil and
         catalog[perm].since_version > catalog_version do
      false
    else
      MapSet.member?(defaults, perm)
    end
  end

  defp handle_permission_error(conn, {:invalid_permission, perm}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_permission", permission: perm})
  end

  defp handle_permission_error(conn, {:permission_exceeds_base_role, perm}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "permission_exceeds_base_role", permission: perm})
  end

  defp handle_permission_error(conn, {:invalid_permission_dependency, perm}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "invalid_permission_dependency", permission: perm})
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
