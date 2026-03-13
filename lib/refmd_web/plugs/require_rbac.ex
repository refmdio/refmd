defmodule RefMDWeb.Plugs.RequireRBAC do
  @moduledoc """
  Plug that enforces RBAC permission checks for workspace-scoped endpoints.

  Usage:
    plug RequireRBAC, permission: "document:read"
    plug RequireRBAC, permission: :membership
    plug RequireRBAC, permission: "member:invite", not_member_status: :not_found

  Options:
    - `permission` (required): permission string or `:membership`
    - `not_member_status`: `:forbidden` (default) or `:not_found`

  Requires RequireAuth (and typically RequirePoP) to run first.
  Resolves workspace_id from path params, fetches membership and role,
  then checks the requested permission against the role's effective permissions.

  Assigns to conn:
    - :workspace_id
    - :workspace_member
    - :workspace_role
  """

  import Plug.Conn
  alias RefMD.Workspaces

  @permission_catalog %{
    "document:read" => %{base_role_ceiling: "viewer", since_version: 1},
    "document:write" => %{base_role_ceiling: "editor", since_version: 1},
    "document:delete" => %{base_role_ceiling: "admin", since_version: 1},
    "document:archive" => %{base_role_ceiling: "editor", since_version: 1},
    "workspace:update" => %{base_role_ceiling: "admin", since_version: 1},
    "workspace:admin" => %{base_role_ceiling: "admin", since_version: 1},
    "workspace:delete" => %{base_role_ceiling: "owner", since_version: 1},
    "member:list" => %{base_role_ceiling: "viewer", since_version: 1},
    "member:invite" => %{base_role_ceiling: "admin", since_version: 1},
    "member:change_role" => %{base_role_ceiling: "admin", since_version: 1},
    "member:remove" => %{base_role_ceiling: "admin", since_version: 1},
    "role:manage" => %{base_role_ceiling: "admin", since_version: 1}
  }

  @base_role_defaults %{
    "owner" => MapSet.new(~w(
        document:read document:write document:delete document:archive
        workspace:update workspace:admin workspace:delete
        member:list member:invite member:change_role member:remove
        role:manage
      )),
    "admin" => MapSet.new(~w(
        document:read document:write document:delete document:archive
        workspace:update workspace:admin
        member:list member:invite member:change_role member:remove
        role:manage
      )),
    "editor" => MapSet.new(~w(document:read document:write document:archive member:list)),
    "viewer" => MapSet.new(~w(document:read member:list))
  }

  @role_power %{"owner" => 4, "admin" => 3, "editor" => 2, "viewer" => 1}

  @spec permission_catalog() :: map()
  def permission_catalog, do: @permission_catalog

  @spec base_role_defaults() :: map()
  def base_role_defaults, do: @base_role_defaults

  @spec role_power() :: map()
  def role_power, do: @role_power

  @spec init(keyword()) :: map()
  def init(opts) do
    permission = Keyword.fetch!(opts, :permission)
    not_member_status = Keyword.get(opts, :not_member_status, :forbidden)

    unless not_member_status in [:forbidden, :not_found] do
      raise ArgumentError,
            "not_member_status must be :forbidden or :not_found, got: #{inspect(not_member_status)}"
    end

    if permission != :membership do
      unless Map.has_key?(@permission_catalog, permission) do
        raise ArgumentError, "Unknown permission: #{inspect(permission)}"
      end
    end

    %{permission: permission, not_member_status: not_member_status}
  end

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{permission: permission, not_member_status: not_member_status}) do
    workspace_id = conn.path_params["workspace_id"]

    if Regex.match?(@uuid_regex, workspace_id || "") do
      do_call(conn, workspace_id, permission, not_member_status)
    else
      conn
      |> put_status(:bad_request)
      |> Phoenix.Controller.json(%{error: "invalid_workspace_id"})
      |> halt()
    end
  end

  defp do_call(conn, workspace_id, permission, not_member_status) do
    user_id = conn.assigns.current_user_id

    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil ->
        deny_not_member(conn, not_member_status)

      {member, role} ->
        conn = assign_workspace_context(conn, workspace_id, member, role)

        if permission == :membership do
          conn
        else
          check_permission(conn, permission, role)
        end
    end
  end

  @spec effective_permissions(Workspaces.WorkspaceRole.t()) :: MapSet.t(String.t())
  def effective_permissions(%{base_role: "owner"}), do: @base_role_defaults["owner"]

  def effective_permissions(role) do
    defaults = @base_role_defaults[role.base_role]
    overrides = role.permissions

    Enum.reduce(@permission_catalog, MapSet.new(), fn {perm_key, perm_info}, acc ->
      if permission_granted?(perm_key, perm_info, role, defaults, overrides) do
        MapSet.put(acc, perm_key)
      else
        acc
      end
    end)
  end

  defp permission_granted?(perm_key, perm_info, role, defaults, overrides) do
    ceiling_power = @role_power[perm_info.base_role_ceiling]
    role_power_val = @role_power[role.base_role]

    role_power_val >= ceiling_power and
      resolve_grant(perm_key, perm_info, role, defaults, overrides)
  end

  defp resolve_grant(perm_key, perm_info, role, defaults, overrides) do
    override = Enum.find(overrides, &(&1.permission == perm_key))

    cond do
      override != nil ->
        override.granted

      role.catalog_version != nil and perm_info.since_version > role.catalog_version ->
        false

      true ->
        MapSet.member?(defaults, perm_key)
    end
  end

  defp check_permission(conn, permission, role) do
    if role.base_role == "owner" do
      conn
    else
      perm_info = @permission_catalog[permission]
      ceiling_power = @role_power[perm_info.base_role_ceiling]
      role_power_val = @role_power[role.base_role]

      if role_power_val < ceiling_power do
        deny(conn)
      else
        check_db_permission(conn, permission, role, perm_info)
      end
    end
  end

  defp check_db_permission(conn, permission, role, perm_info) do
    override = Enum.find(role.permissions, &(&1.permission == permission))

    cond do
      override != nil ->
        if override.granted, do: conn, else: deny(conn)

      role.catalog_version != nil and perm_info.since_version > role.catalog_version ->
        deny(conn)

      true ->
        defaults = @base_role_defaults[role.base_role]
        if MapSet.member?(defaults, permission), do: conn, else: deny(conn)
    end
  end

  defp deny(conn) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{error: "permission_denied"})
    |> halt()
  end

  defp deny_not_member(conn, :forbidden) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{error: "not_a_member"})
    |> halt()
  end

  defp deny_not_member(conn, :not_found) do
    conn
    |> put_status(:not_found)
    |> Phoenix.Controller.json(%{error: "not_found"})
    |> halt()
  end

  defp assign_workspace_context(conn, workspace_id, member, role) do
    conn
    |> assign(:workspace_id, workspace_id)
    |> assign(:workspace_member, member)
    |> assign(:workspace_role, role)
  end
end
