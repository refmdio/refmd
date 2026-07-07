defmodule RefMD.Workspaces.Roles do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Repo

  alias RefMD.Workspaces.{
    WorkspaceRole,
    WorkspaceRolePermission
  }

  alias RefMD.Workspaces.Roles.Authorization

  @current_catalog_version 1

  def list_workspace_roles(workspace_id) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^workspace_id,
      preload: [:permissions],
      order_by: [asc: r.created_at]
    )
    |> Repo.all()
  end

  def create_custom_role(workspace_id, name, base_role, permissions \\ nil) do
    with :ok <- validate_custom_base_role(base_role),
         {:ok, resolved_permissions} <-
           Authorization.validate_create_permissions(permissions, base_role) do
      Repo.transaction(fn ->
        create_custom_role_transaction(workspace_id, name, base_role, resolved_permissions)
      end)
    end
  end

  def update_role(role, attrs, opts \\ []) do
    permissions = Keyword.get(opts, :permissions)

    with {:ok, {resolved_permissions, submitted_keys}} <-
           Authorization.validate_update_permissions(permissions, role) do
      Repo.transaction(fn ->
        update_role_transaction(role, attrs, resolved_permissions, submitted_keys)
      end)
    end
  end

  def delete_role(role) do
    Repo.transaction(fn ->
      fresh =
        from(r in WorkspaceRole, where: r.id == ^role.id, lock: "FOR UPDATE")
        |> Repo.one()

      if fresh == nil, do: Repo.rollback(:role_in_use)
      if fresh.is_default, do: Repo.rollback(:cannot_delete_default_role)

      from(p in WorkspaceRolePermission, where: p.role_id == ^role.id)
      |> Repo.delete_all()

      invitation_count = count_role_invitations(role.id)

      try do
        case Repo.delete(fresh) do
          {:ok, _} -> invitation_count
          {:error, _} -> Repo.rollback(:role_in_use)
        end
      rescue
        Ecto.ConstraintError -> Repo.rollback(:role_in_use)
      end
    end)
  end

  def get_default_role_with_permissions(workspace_id) do
    case get_default_role(workspace_id) do
      nil -> nil
      role -> get_role_with_permissions(workspace_id, role.id)
    end
  end

  def get_role_with_permissions(workspace_id, role_id) do
    query =
      from(r in WorkspaceRole,
        left_join: p in WorkspaceRolePermission,
        on: p.role_id == r.id,
        where: r.id == ^role_id and r.workspace_id == ^workspace_id,
        select: {r, p}
      )

    case Repo.all(query) do
      [] ->
        nil

      rows ->
        {role, _} = hd(rows)

        permissions =
          rows
          |> Enum.map(fn {_, p} -> p end)
          |> Enum.reject(&is_nil/1)

        %{role | permissions: permissions}
    end
  end

  def get_default_role(workspace_id) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^workspace_id and r.is_default == true
    )
    |> Repo.one()
  end

  # ── Private Helpers ─────────────────────────────

  defp create_custom_role_transaction(workspace_id, name, base_role, resolved_permissions) do
    role =
      %WorkspaceRole{created_at: DateTime.utc_now()}
      |> WorkspaceRole.changeset(%{
        workspace_id: workspace_id,
        name: name,
        base_role: base_role,
        catalog_version: @current_catalog_version
      })
      |> insert_role_or_rollback()

    save_permission_overrides(role.id, resolved_permissions || [])
    Repo.preload(role, :permissions)
  end

  defp insert_role_or_rollback(changeset) do
    case Repo.insert(changeset) do
      {:ok, role} -> role
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp update_role_transaction(role, attrs, resolved_permissions, submitted_keys) do
    role_attrs = Map.reject(attrs, fn {_k, v} -> is_nil(v) end)
    updated = apply_role_attrs(role, role_attrs)
    merge_permissions_if_present(role.id, resolved_permissions, submitted_keys)
    Repo.preload(updated, :permissions, force: true)
  end

  defp apply_role_attrs(role, role_attrs) do
    cond do
      role_attrs[:is_default] == true and role.base_role == "guest" ->
        Repo.rollback(:guest_role_default_not_allowed)

      role_attrs[:is_default] == true and not role.is_default ->
        swap_default_role(role, role_attrs)

      role_attrs[:is_default] == false and role.is_default ->
        Repo.rollback(:cannot_unset_default_role)

      true ->
        update_role_fields(role, role_attrs)
    end
  end

  defp swap_default_role(role, role_attrs) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^role.workspace_id and r.is_default == true
    )
    |> Repo.update_all(set: [is_default: false])

    case role
         |> WorkspaceRole.changeset(Map.put(role_attrs, :is_default, true))
         |> Repo.update() do
      {:ok, updated} -> updated
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp update_role_fields(role, role_attrs) do
    changeset_attrs = build_changeset_attrs(role_attrs)

    case role
         |> WorkspaceRole.changeset(changeset_attrs)
         |> Repo.update() do
      {:ok, updated} -> updated
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp build_changeset_attrs(role_attrs) do
    base = Map.take(role_attrs, [:name])

    if Map.has_key?(role_attrs, :is_default),
      do: Map.put(base, :is_default, role_attrs[:is_default]),
      else: base
  end

  defp merge_permissions_if_present(_role_id, nil, _submitted_keys), do: :ok
  defp merge_permissions_if_present(_role_id, _permissions, []), do: :ok

  defp merge_permissions_if_present(role_id, permissions, submitted_keys) do
    keys_to_delete = submitted_keys || Enum.map(permissions, fn %{"permission" => p} -> p end)

    from(p in WorkspaceRolePermission,
      where: p.role_id == ^role_id and p.permission in ^keys_to_delete
    )
    |> Repo.delete_all()

    submitted_set = if submitted_keys, do: MapSet.new(submitted_keys), else: nil

    permissions_to_save =
      if submitted_set do
        Enum.filter(permissions, fn %{"permission" => p} -> MapSet.member?(submitted_set, p) end)
      else
        permissions
      end

    save_permission_overrides(role_id, permissions_to_save)
  end

  defp save_permission_overrides(_role_id, []), do: :ok

  defp save_permission_overrides(role_id, permissions) do
    Enum.each(permissions, fn %{"permission" => perm, "granted" => granted} ->
      case %WorkspaceRolePermission{}
           |> WorkspaceRolePermission.changeset(%{
             role_id: role_id,
             permission: perm,
             granted: granted
           })
           |> Repo.insert() do
        {:ok, _} -> :ok
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  defp count_role_invitations(_role_id), do: 0

  defp validate_custom_base_role("owner"), do: {:error, :owner_role_not_allowed}
  defp validate_custom_base_role(base_role) when base_role in ~w(admin editor viewer), do: :ok
  defp validate_custom_base_role(_base_role), do: {:error, :invalid_base_role}
end
