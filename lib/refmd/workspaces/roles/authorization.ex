defmodule RefMD.Workspaces.Roles.Authorization do
  @moduledoc false

  @permission_catalog %{
    "document:read" => %{base_role_ceiling: "viewer", since_version: 1},
    "document:write" => %{base_role_ceiling: "editor", since_version: 1},
    "document:manage_share" => %{base_role_ceiling: "editor", since_version: 1},
    "document:delete" => %{base_role_ceiling: "admin", since_version: 1},
    "document:archive" => %{base_role_ceiling: "editor", since_version: 1},
    "workspace:update" => %{base_role_ceiling: "admin", since_version: 1},
    "workspace:features" => %{base_role_ceiling: "admin", since_version: 1},
    "workspace:admin" => %{base_role_ceiling: "admin", since_version: 1},
    "workspace:delete" => %{base_role_ceiling: "owner", since_version: 1},
    "member:list" => %{base_role_ceiling: "viewer", since_version: 1},
    "member:invite" => %{base_role_ceiling: "admin", since_version: 1},
    "guest:invite" => %{base_role_ceiling: "admin", since_version: 1},
    "member:change_role" => %{base_role_ceiling: "admin", since_version: 1},
    "member:remove" => %{base_role_ceiling: "admin", since_version: 1},
    "role:manage" => %{base_role_ceiling: "admin", since_version: 1}
  }

  @base_role_defaults %{
    "owner" => MapSet.new(~w(
        document:read document:write document:manage_share document:delete document:archive
        workspace:update workspace:features workspace:admin workspace:delete
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "admin" => MapSet.new(~w(
        document:read document:write document:manage_share document:delete document:archive
        workspace:update workspace:features workspace:admin
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "editor" =>
      MapSet.new(
        ~w(document:read document:write document:manage_share document:archive member:list)
      ),
    "viewer" => MapSet.new(~w(document:read member:list)),
    "guest" => MapSet.new(~w(document:read document:write document:archive))
  }

  @role_power %{"owner" => 4, "admin" => 3, "editor" => 2, "viewer" => 1, "guest" => 2}

  @permission_dependencies [
    {"document:write", "document:read"},
    {"document:manage_share", "document:read"},
    {"document:read", "member:list"}
  ]

  def validate_create_permissions(nil, _base_role), do: {:ok, nil}

  def validate_create_permissions(permissions, base_role) when is_list(permissions) do
    role_power_val = @role_power[base_role]

    with :ok <- validate_permission_keys(permissions),
         :ok <- validate_permission_ceilings(permissions, role_power_val) do
      case validate_permission_dependencies(permissions, base_role, nil) do
        :ok -> {:ok, filter_default_matching_overrides(permissions, base_role, nil)}
        error -> error
      end
    end
  end

  def validate_create_permissions(_permissions, _base_role),
    do: {:error, {:invalid_permission, nil}}

  def validate_update_permissions(nil, _role), do: {:ok, {nil, nil}}

  def validate_update_permissions(permissions, role) when is_list(permissions) do
    role_power_val = @role_power[role.base_role]

    with :ok <- validate_permission_keys(permissions),
         :ok <- validate_permission_ceilings(permissions, role_power_val) do
      merged = merge_with_existing_overrides(permissions, role)

      case validate_permission_dependencies(merged, role.base_role, role.catalog_version) do
        :ok ->
          {:ok,
           {filter_default_matching_overrides(merged, role.base_role, role.catalog_version),
            Enum.map(permissions, & &1["permission"])}}

        error ->
          error
      end
    end
  end

  def validate_update_permissions(_permissions, _role), do: {:error, {:invalid_permission, nil}}

  def validate_role_assignment(actor_role, target_role) do
    actor_power = @role_power[actor_role.base_role]
    target_power = @role_power[target_role.base_role]

    cond do
      target_power > actor_power ->
        {:error, :role_escalation}

      not MapSet.subset?(effective_permissions(target_role), effective_permissions(actor_role)) ->
        {:error, :permission_escalation}

      true ->
        :ok
    end
  end

  def permission_defined?(permission), do: Map.has_key?(@permission_catalog, permission)

  def effective_permissions(%{base_role: "owner"}), do: @base_role_defaults["owner"]

  def effective_permissions(role) do
    defaults = Map.get(@base_role_defaults, role.base_role, MapSet.new())
    overrides = Map.get(role, :permissions, [])

    Enum.reduce(@permission_catalog, MapSet.new(), fn {perm_key, perm_info}, acc ->
      if permission_granted?(perm_key, perm_info, role, defaults, overrides) do
        MapSet.put(acc, perm_key)
      else
        acc
      end
    end)
  end

  def permission_granted?(role, permission) when is_binary(permission) do
    case Map.get(@permission_catalog, permission) do
      nil ->
        false

      perm_info ->
        defaults = Map.get(@base_role_defaults, role.base_role, MapSet.new())
        overrides = Map.get(role, :permissions, [])
        permission_granted?(permission, perm_info, role, defaults, overrides)
    end
  end

  defp permission_granted?(perm_key, perm_info, role, defaults, overrides) do
    if role.base_role == "guest" and not MapSet.member?(defaults, perm_key) do
      false
    else
      ceiling_power = @role_power[perm_info.base_role_ceiling]
      role_power_val = @role_power[role.base_role]

      role_power_val >= ceiling_power and
        resolve_grant(perm_key, perm_info, role, defaults, overrides)
    end
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

  defp merge_with_existing_overrides(submitted, role) do
    existing_map =
      Map.new(role.permissions, fn p ->
        {p.permission, %{"permission" => p.permission, "granted" => p.granted}}
      end)

    submitted_map =
      Map.new(submitted, fn %{"permission" => p, "granted" => g} ->
        {p, %{"permission" => p, "granted" => g}}
      end)

    submitted_map
    |> Map.merge(existing_map, fn _key, submitted_value, _existing_value -> submitted_value end)
    |> Map.values()
  end

  defp validate_permission_keys(permissions) do
    invalid =
      Enum.find(permissions, fn entry ->
        not is_map_key(entry, "permission") or not is_map_key(entry, "granted") or
          not is_binary(entry["permission"]) or not is_boolean(entry["granted"]) or
          not Map.has_key?(@permission_catalog, entry["permission"])
      end)

    if invalid, do: {:error, {:invalid_permission, permission_value(invalid)}}, else: :ok
  end

  defp permission_value(%{"permission" => permission}), do: permission
  defp permission_value(_), do: nil

  defp validate_permission_ceilings(permissions, role_power_val) do
    violation =
      Enum.find(permissions, fn %{"permission" => perm} ->
        @role_power[@permission_catalog[perm].base_role_ceiling] > role_power_val
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
    if catalog_version != nil and @permission_catalog[perm] != nil and
         @permission_catalog[perm].since_version > catalog_version do
      false
    else
      @base_role_defaults
      |> Map.get(base_role, MapSet.new())
      |> MapSet.member?(perm)
    end
  end
end
