defmodule RefMD.Workspaces.Roles do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Repo

  alias RefMD.Workspaces.{
    WorkspaceInvitation,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  @current_catalog_version 1

  @spec list_workspace_roles(Ecto.UUID.t()) :: [WorkspaceRole.t()]
  def list_workspace_roles(workspace_id) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^workspace_id,
      preload: [:permissions],
      order_by: [asc: r.created_at]
    )
    |> Repo.all()
  end

  @spec create_custom_role(Ecto.UUID.t(), String.t(), String.t(), list() | nil) ::
          {:ok, WorkspaceRole.t()} | {:error, term()}
  def create_custom_role(workspace_id, name, base_role, permissions \\ nil)
      when base_role in ~w(admin editor viewer) do
    Repo.transaction(fn ->
      case %WorkspaceRole{created_at: DateTime.utc_now()}
           |> WorkspaceRole.changeset(%{
             workspace_id: workspace_id,
             name: name,
             base_role: base_role,
             catalog_version: @current_catalog_version
           })
           |> Repo.insert() do
        {:ok, role} ->
          save_permission_overrides(role.id, permissions || [])
          Repo.preload(role, :permissions)

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  @spec update_role(WorkspaceRole.t(), map(), keyword()) ::
          {:ok, WorkspaceRole.t()} | {:error, term()}
  def update_role(role, attrs, opts \\ []) do
    permissions = Keyword.get(opts, :permissions)
    submitted_keys = Keyword.get(opts, :submitted_keys)

    Repo.transaction(fn ->
      role_attrs = Map.reject(attrs, fn {_k, v} -> is_nil(v) end)
      updated = apply_role_attrs(role, role_attrs)
      merge_permissions_if_present(role.id, permissions, submitted_keys)
      Repo.preload(updated, :permissions, force: true)
    end)
  end

  @spec delete_role(WorkspaceRole.t()) ::
          {:ok, non_neg_integer()} | {:error, :role_in_use | :cannot_delete_default_role}
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

  @spec get_default_role_with_permissions(Ecto.UUID.t()) :: WorkspaceRole.t() | nil
  def get_default_role_with_permissions(workspace_id) do
    case get_default_role(workspace_id) do
      nil -> nil
      role -> get_role_with_permissions(workspace_id, role.id)
    end
  end

  @spec get_role_with_permissions(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceRole.t() | nil
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

  @spec get_default_role(Ecto.UUID.t()) :: WorkspaceRole.t() | nil
  def get_default_role(workspace_id) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^workspace_id and r.is_default == true
    )
    |> Repo.one()
  end

  # ── Private Helpers ─────────────────────────────

  defp apply_role_attrs(role, role_attrs) do
    cond do
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

  defp count_role_invitations(role_id) do
    from(i in WorkspaceInvitation, where: i.role_id == ^role_id)
    |> Repo.aggregate(:count)
  end
end
