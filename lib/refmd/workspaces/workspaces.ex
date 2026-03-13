defmodule RefMD.Workspaces do
  @moduledoc """
  The Workspaces context. Manages workspaces, members, roles, and permissions.
  """

  require Logger

  import Ecto.Query
  alias Ecto.Adapters.SQL, as: EctoSQL
  alias RefMD.Repo

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceInvitation,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  @spec create_default_workspace(Ecto.UUID.t(), String.t()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def create_default_workspace(user_id, name) do
    slug = generate_slug(name)

    Repo.transaction(fn ->
      workspace =
        insert_or_rollback(
          %Workspace{}
          |> Workspace.changeset(%{name: name, slug: slug, owner_id: user_id})
        )

      roles =
        for {base_role, role_name} <- [
              {"owner", "Owner"},
              {"admin", "Admin"},
              {"editor", "Editor"},
              {"viewer", "Viewer"}
            ] do
          insert_or_rollback(
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
          )
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      insert_or_rollback(
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: true,
          joined_at: DateTime.utc_now()
        })
      )

      workspace
    end)
  end

  defp insert_or_rollback(changeset) do
    case Repo.insert(changeset) do
      {:ok, record} -> record
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  @spec create_workspace(Ecto.UUID.t(), String.t(), map()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def create_workspace(user_id, name, opts \\ %{}) do
    slug = generate_slug(name)

    attrs =
      %{name: name, slug: slug, owner_id: user_id}
      |> maybe_put(:description, opts[:description])
      |> maybe_put(:icon, opts[:icon])

    Repo.transaction(fn ->
      workspace =
        insert_or_rollback(
          %Workspace{}
          |> Workspace.changeset(attrs)
        )

      roles =
        for {base_role, role_name} <- [
              {"owner", "Owner"},
              {"admin", "Admin"},
              {"editor", "Editor"},
              {"viewer", "Viewer"}
            ] do
          insert_or_rollback(
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
          )
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      insert_or_rollback(
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: false,
          joined_at: DateTime.utc_now()
        })
      )

      workspace
    end)
  end

  @spec get_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
  def get_workspace(id), do: Repo.get(Workspace, id)

  @spec update_workspace(Workspace.t(), map()) ::
          {:ok, Workspace.t()} | {:error, Ecto.Changeset.t()}
  def update_workspace(%Workspace{} = workspace, attrs) do
    workspace
    |> Workspace.update_changeset(attrs)
    |> Repo.update()
  end

  @spec delete_workspace(Workspace.t()) :: {:ok, Workspace.t()} | {:error, Ecto.Changeset.t()}
  def delete_workspace(%Workspace{} = workspace) do
    Repo.delete(workspace)
  end

  @spec update_current_kek_version(Ecto.UUID.t(), integer()) ::
          {non_neg_integer(), nil | [term()]}
  def update_current_kek_version(workspace_id, version) do
    from(w in Workspace, where: w.id == ^workspace_id)
    |> Repo.update_all(set: [current_kek_version: version])
  end

  @spec initialize_kek_version(Ecto.UUID.t()) :: {non_neg_integer(), nil | [term()]}
  def initialize_kek_version(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id and w.current_kek_version == 0)
    |> Repo.update_all(set: [current_kek_version: 1])
  end

  @spec get_user_default_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
  def get_user_default_workspace(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id and wm.is_default == true,
      select: w,
      limit: 1
    )
    |> Repo.one()
  end

  @spec list_user_workspaces(Ecto.UUID.t()) :: [
          %{
            workspace: Workspace.t(),
            is_default: boolean(),
            role_id: Ecto.UUID.t(),
            base_role: String.t()
          }
        ]
  def list_user_workspaces(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id,
      where: wm.user_id == ^user_id,
      select: %{
        workspace: w,
        is_default: wm.is_default,
        role_id: wm.role_id,
        base_role: r.base_role
      },
      order_by: [asc: w.name]
    )
    |> Repo.all()
  end

  @spec get_user_workspace_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def get_user_workspace_ids(user_id) do
    from(wm in WorkspaceMember,
      where: wm.user_id == ^user_id,
      select: wm.workspace_id
    )
    |> Repo.all()
  end

  @spec get_user_workspace_ids_with_kek_version(Ecto.UUID.t()) :: [{Ecto.UUID.t(), integer()}]
  def get_user_workspace_ids_with_kek_version(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id,
      select: {wm.workspace_id, w.current_kek_version}
    )
    |> Repo.all()
  end

  @spec mark_kek_rotation_needed([Ecto.UUID.t()], Ecto.UUID.t()) ::
          {non_neg_integer(), nil | [term()]}
  def mark_kek_rotation_needed(workspace_ids, initiator_user_id) when workspace_ids != [] do
    from(w in Workspace,
      where: w.id in ^workspace_ids and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [needs_kek_rotation: true, kek_rotation_initiator_user_id: initiator_user_id]
    )
  end

  def mark_kek_rotation_needed([], _initiator_user_id), do: {0, nil}

  @spec mark_dek_rotation_needed([Ecto.UUID.t()]) :: {non_neg_integer(), nil | [term()]}
  def mark_dek_rotation_needed(workspace_ids) when workspace_ids != [] do
    from(d in RefMD.Documents.Document,
      where: d.workspace_id in ^workspace_ids and d.needs_dek_rotation == false
    )
    |> Repo.update_all(set: [needs_dek_rotation: true])
  end

  def mark_dek_rotation_needed([]), do: {0, nil}

  @spec start_kek_rotation(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Workspace.t()} | {:error, :not_found | :kek_rotation_already_in_progress}
  def start_kek_rotation(workspace_id, initiator_user_id) do
    from(w in Workspace,
      where: w.id == ^workspace_id and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: initiator_user_id
      ]
    )
    |> case do
      {1, _} ->
        {:ok, Repo.get!(Workspace, workspace_id)}

      {0, _} ->
        case Repo.get(Workspace, workspace_id) do
          nil -> {:error, :not_found}
          %{needs_kek_rotation: true} -> {:error, :kek_rotation_already_in_progress}
        end
    end
  end

  @spec complete_kek_rotation(Ecto.UUID.t(), integer(), keyword()) :: :ok | {:error, term()}
  def complete_kek_rotation(workspace_id, new_kek_version, opts \\ []) do
    envelope_checks = Keyword.get(opts, :envelope_checks, fn -> :ok end)

    Repo.transaction(fn ->
      workspace =
        from(w in Workspace,
          where: w.id == ^workspace_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      cond do
        workspace == nil ->
          Repo.rollback(:not_found)

        not workspace.needs_kek_rotation ->
          Repo.rollback(:not_in_rotation)

        workspace.current_kek_version >= new_kek_version ->
          Repo.rollback(:version_not_monotonic)

        true ->
          apply_rotation_completion(workspace_id, new_kek_version, envelope_checks)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_rotation_completion(workspace_id, new_kek_version, envelope_checks) do
    case envelope_checks.() do
      :ok ->
        # Deactivate old KEK version keys (min_kek_version = new version rejects old KEK)
        from(k in RefMD.Encryption.WorkspaceEncryptedKey,
          where:
            k.workspace_id == ^workspace_id and
              k.key_version < ^new_kek_version and
              k.is_active == true
        )
        |> Repo.update_all(set: [is_active: false])

        from(w in Workspace, where: w.id == ^workspace_id)
        |> Repo.update_all(
          set: [
            current_kek_version: new_kek_version,
            min_kek_version: new_kek_version,
            needs_kek_rotation: false,
            kek_rotation_initiator_user_id: nil
          ]
        )

        :ok

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  @spec list_workspaces_needing_kek_rotation() :: [map()]
  def list_workspaces_needing_kek_rotation do
    from(w in Workspace,
      where: w.needs_kek_rotation == true,
      select: %{
        workspace_id: w.id,
        initiator_user_id: w.kek_rotation_initiator_user_id,
        current_kek_version: w.current_kek_version
      }
    )
    |> Repo.all()
  end

  @spec list_workspace_member_user_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def list_workspace_member_user_ids(workspace_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id,
      select: wm.user_id
    )
    |> Repo.all()
  end

  @spec get_workspace_member(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceMember.t() | nil
  def get_workspace_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
    )
    |> Repo.one()
  end

  @spec get_member_role(Ecto.UUID.t(), Ecto.UUID.t()) :: String.t() | nil
  def get_member_role(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: r.base_role
    )
    |> Repo.one()
  end

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

  @spec get_member_with_role(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {WorkspaceMember.t(), WorkspaceRole.t()} | nil
  def get_member_with_role(workspace_id, user_id) do
    query =
      from(wm in WorkspaceMember,
        join: r in WorkspaceRole,
        on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
        left_join: p in WorkspaceRolePermission,
        on: p.role_id == r.id,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
        select: {wm, r, p}
      )

    case Repo.all(query) do
      [] ->
        nil

      rows ->
        {member, role, _} = hd(rows)

        permissions =
          rows
          |> Enum.map(fn {_, _, p} -> p end)
          |> Enum.reject(&is_nil/1)

        {member, %{role | permissions: permissions}}
    end
  end

  @spec list_workspace_members(Ecto.UUID.t()) :: [map()]
  def list_workspace_members(workspace_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      join: u in RefMD.Users.User,
      on: u.id == wm.user_id,
      where: wm.workspace_id == ^workspace_id,
      select: %{
        user_id: wm.user_id,
        email: u.email,
        name: u.name,
        role_id: wm.role_id,
        role_name: r.name,
        base_role: r.base_role,
        is_default: wm.is_default,
        joined_at: wm.joined_at
      },
      order_by: [asc: wm.joined_at]
    )
    |> Repo.all()
  end

  @spec change_member_role(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, WorkspaceMember.t()} | {:error, atom()}
  def change_member_role(workspace_id, target_user_id, new_role_id, actor_user_id) do
    Repo.transaction(fn ->
      owner_rows = lock_owner_rows(workspace_id)

      new_role =
        case Repo.get(WorkspaceRole, new_role_id) do
          nil -> nil
          r -> Repo.preload(r, :permissions)
        end

      ctx = %{
        actor_role: fetch_role_for_user(workspace_id, actor_user_id),
        target_role: fetch_role_for_user(workspace_id, target_user_id),
        new_role: new_role,
        owner_count: count_owners(owner_rows)
      }

      with :ok <- check_rbac_permission(ctx.actor_role, "member:change_role"),
           :ok <- validate_role_change(ctx, workspace_id) do
        do_change_role(workspace_id, target_user_id, new_role_id)
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  end

  defp validate_role_change(%{actor_role: nil}, _workspace_id), do: {:error, :actor_not_member}
  defp validate_role_change(%{target_role: nil}, _workspace_id), do: {:error, :target_not_member}
  defp validate_role_change(%{new_role: nil}, _workspace_id), do: {:error, :invalid_role}

  defp validate_role_change(ctx, workspace_id) do
    cond do
      ctx.new_role.workspace_id != workspace_id ->
        {:error, :invalid_role}

      ctx.target_role.base_role == "owner" and ctx.actor_role.base_role != "owner" ->
        {:error, :cannot_modify_owner}

      role_power(ctx.new_role.base_role) > role_power(ctx.actor_role.base_role) ->
        {:error, :role_escalation}

      ctx.target_role.base_role == "owner" and ctx.new_role.base_role != "owner" and
          ctx.owner_count <= 1 ->
        {:error, :last_owner}

      true ->
        check_effective_permissions_subset(ctx.new_role, ctx.actor_role)
    end
  end

  defp check_effective_permissions_subset(new_role, actor_role) do
    alias RefMDWeb.Plugs.RequireRBAC

    new_perms = RequireRBAC.effective_permissions(new_role)
    actor_perms = RequireRBAC.effective_permissions(actor_role)

    if MapSet.subset?(new_perms, actor_perms) do
      :ok
    else
      {:error, :permission_escalation}
    end
  end

  @spec remove_member(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, atom()}
  def remove_member(workspace_id, target_user_id, actor_user_id) do
    result =
      Repo.transaction(fn ->
        owner_rows = lock_owner_rows(workspace_id)
        target_role = fetch_role_for_user(workspace_id, target_user_id)

        case validate_removal(
               workspace_id,
               target_user_id,
               actor_user_id,
               target_role,
               owner_rows
             ) do
          :ok ->
            member = do_remove_member(workspace_id, target_user_id)
            revoke_removed_member_invitations(workspace_id, target_user_id)
            member

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
      |> normalize_transaction_result()

    case result do
      {:ok, member} ->
        initiator =
          if target_user_id == actor_user_id do
            find_rotation_initiator(workspace_id)
          else
            actor_user_id
          end

        best_effort_flag_kek_rotation(workspace_id, initiator)
        {:ok, member}

      error ->
        error
    end
  end

  defp find_rotation_initiator(workspace_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id,
      where: wm.workspace_id == ^workspace_id and r.base_role in ["owner", "admin"],
      order_by: [asc: fragment("CASE ? WHEN 'owner' THEN 0 ELSE 1 END", r.base_role)],
      limit: 1,
      select: wm.user_id
    )
    |> Repo.one!()
  end

  defp revoke_removed_member_invitations(workspace_id, target_user_id) do
    case get_user_email(target_user_id) do
      nil -> :ok
      email -> revoke_invitations_for_email(workspace_id, email)
    end
  end

  defp get_user_email(user_id) do
    case Repo.get(RefMD.Users.User, user_id) do
      nil -> nil
      user -> user.email
    end
  end

  defp best_effort_flag_kek_rotation(workspace_id, initiator_user_id) do
    from(w in Workspace,
      where: w.id == ^workspace_id and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: initiator_user_id
      ]
    )

    mark_dek_rotation_needed([workspace_id])
  rescue
    e ->
      Logger.error("Failed to flag rotation for workspace #{workspace_id}: #{inspect(e)}")

      alias RefMD.Workers.RetryRotationMarking

      case %{workspace_id: workspace_id, initiator_user_id: initiator_user_id}
           |> RetryRotationMarking.new()
           |> Oban.insert() do
        {:ok, _job} ->
          :ok

        {:error, reason} ->
          Logger.error(
            "Failed to enqueue rotation retry for workspace #{workspace_id}: #{inspect(reason)}"
          )
      end
  end

  defp validate_removal(_ws_id, _target, _actor, nil, _owners), do: {:error, :target_not_member}

  defp validate_removal(_ws_id, _target, _actor, target_role, owner_rows)
       when target_role.base_role == "owner" and length(owner_rows) <= 1,
       do: {:error, :last_owner}

  defp validate_removal(_ws_id, user_id, user_id, _target_role, _owners), do: :ok

  defp validate_removal(workspace_id, _target, actor_user_id, target_role, _owners) do
    actor_role = fetch_role_for_user(workspace_id, actor_user_id)

    cond do
      actor_role == nil ->
        {:error, :actor_not_member}

      target_role.base_role == "owner" and actor_role.base_role != "owner" ->
        {:error, :cannot_modify_owner}

      true ->
        check_rbac_permission(actor_role, "member:remove")
    end
  end

  defp check_rbac_permission(nil, _permission), do: {:error, :actor_not_member}

  defp check_rbac_permission(role, permission) do
    alias RefMDWeb.Plugs.RequireRBAC

    perms = RequireRBAC.effective_permissions(role)
    if MapSet.member?(perms, permission), do: :ok, else: {:error, :permission_denied}
  end

  defp lock_owner_rows(workspace_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      where: wm.workspace_id == ^workspace_id and r.base_role == "owner",
      lock: "FOR UPDATE",
      select: wm.user_id
    )
    |> Repo.all()
  end

  defp fetch_role_for_user(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: r
    )
    |> Repo.one()
    |> maybe_preload_permissions()
  end

  defp maybe_preload_permissions(nil), do: nil
  defp maybe_preload_permissions(role), do: Repo.preload(role, :permissions)

  defp count_owners(owner_user_ids), do: length(owner_user_ids)

  defp role_power("owner"), do: 4
  defp role_power("admin"), do: 3
  defp role_power("editor"), do: 2
  defp role_power("viewer"), do: 1

  defp do_change_role(workspace_id, user_id, new_role_id) do
    {1, _} =
      from(wm in WorkspaceMember,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
      )
      |> Repo.update_all(set: [role_id: new_role_id])

    Repo.one!(
      from(wm in WorkspaceMember,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
      )
    )
  end

  defp do_remove_member(workspace_id, user_id) do
    member =
      Repo.one!(
        from(wm in WorkspaceMember,
          where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
        )
      )

    Repo.delete!(member)
    member
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}

  # ── Invitations ────────────────────────────────────────

  @max_serialization_retries 3

  @spec create_invitation(map()) :: {:ok, WorkspaceInvitation.t()} | {:error, term()}
  def create_invitation(attrs) do
    create_invitation_with_retry(attrs, 0)
  end

  defp create_invitation_with_retry(_attrs, @max_serialization_retries) do
    {:error, :serialization_failure}
  end

  defp create_invitation_with_retry(attrs, attempt) do
    case do_create_invitation(attrs) do
      {:error, :serialization_failure} ->
        create_invitation_with_retry(attrs, attempt + 1)

      other ->
        other
    end
  end

  defp do_create_invitation(attrs) do
    Repo.transaction(fn ->
      EctoSQL.query!(Repo, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", [])

      workspace = lock_workspace_for_share(attrs.workspace_id)

      with :ok <- validate_invitation_creation(workspace, attrs),
           {:ok, actor_role} <- lock_actor_role(attrs.workspace_id, attrs.invited_by),
           :ok <- check_rbac_permission(actor_role, "member:invite"),
           {:ok, target_role} <- resolve_invitation_role(attrs),
           :ok <- validate_escalation(actor_role, target_role),
           {:ok, invitation} <- insert_invitation(attrs, target_role) do
        invitation
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  rescue
    e in Postgrex.Error ->
      case e.postgres.code do
        :serialization_failure -> {:error, :serialization_failure}
        _ -> reraise e, __STACKTRACE__
      end
  end

  defp lock_workspace_for_share(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, lock: "FOR SHARE")
    |> Repo.one()
  end

  defp lock_actor_role(workspace_id, user_id) do
    query =
      from(wm in WorkspaceMember,
        join: r in WorkspaceRole,
        on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
        left_join: p in WorkspaceRolePermission,
        on: p.role_id == r.id,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
        lock: fragment("FOR SHARE OF ?, ?", wm, r),
        select: {wm, r, p}
      )

    case Repo.all(query) do
      [] ->
        {:error, :not_a_member}

      rows ->
        {_member, role, _} = hd(rows)

        permissions =
          rows
          |> Enum.map(fn {_, _, p} -> p end)
          |> Enum.reject(&is_nil/1)

        {:ok, %{role | permissions: permissions}}
    end
  end

  defp validate_invitation_creation(nil, _attrs), do: {:error, :workspace_not_found}

  defp validate_invitation_creation(workspace, attrs) do
    cond do
      workspace.needs_kek_rotation ->
        {:error, :kek_rotation_in_progress}

      workspace.current_kek_version == 0 ->
        {:error, :encryption_setup_incomplete}

      attrs.kek_version != workspace.current_kek_version ->
        {:error, :kek_version_mismatch}

      true ->
        :ok
    end
  end

  defp resolve_invitation_role(%{role_id: nil, workspace_id: workspace_id}) do
    case get_default_role_with_permissions(workspace_id) do
      nil -> {:error, :no_default_role}
      role -> {:ok, role}
    end
  end

  defp resolve_invitation_role(%{role_id: role_id, workspace_id: workspace_id}) do
    case get_role_with_permissions(workspace_id, role_id) do
      nil -> {:error, :invalid_role}
      role -> {:ok, role}
    end
  end

  defp validate_escalation(actor_role, target_role) do
    alias RefMDWeb.Plugs.RequireRBAC

    actor_power = RequireRBAC.role_power()[actor_role.base_role]
    target_power = RequireRBAC.role_power()[target_role.base_role]

    cond do
      target_power > actor_power ->
        {:error, :role_escalation}

      not MapSet.subset?(
        RequireRBAC.effective_permissions(target_role),
        RequireRBAC.effective_permissions(actor_role)
      ) ->
        {:error, :permission_escalation}

      true ->
        :ok
    end
  end

  defp insert_invitation(attrs, target_role) do
    role_id = target_role.id
    now = DateTime.utc_now()
    expires_at = attrs[:expires_at] || DateTime.add(now, 7 * 86_400)

    result =
      %WorkspaceInvitation{}
      |> WorkspaceInvitation.changeset(%{
        id: attrs.invitation_id,
        workspace_id: attrs.workspace_id,
        token_hash: attrs.token_hash,
        token_prefix: attrs.token_prefix,
        role_id: role_id,
        invited_by: attrs.invited_by,
        invited_email: attrs.invited_email,
        encrypted_kek: attrs.encrypted_kek,
        kek_nonce: attrs.kek_nonce,
        kek_version: attrs.kek_version,
        expires_at: expires_at,
        created_at: now
      })
      |> Repo.insert()

    case result do
      {:ok, invitation} ->
        {:ok, invitation}

      {:error, changeset} ->
        map_insert_constraint_error(changeset)
    end
  end

  defp map_insert_constraint_error(changeset) do
    cond do
      has_constraint_error?(changeset, :token_hash, "has already been taken") ->
        {:error, :token_hash_already_exists}

      has_constraint_error?(changeset, :id, "has already been taken") ->
        {:error, :id_already_exists}

      has_constraint_error?(changeset, :workspace_id) ->
        {:error, :workspace_not_found}

      has_constraint_error?(changeset, :role_id) ->
        {:error, :invalid_role}

      true ->
        {:error, :validation_error}
    end
  end

  defp has_constraint_error?(changeset, field, message \\ nil) do
    Enum.any?(changeset.errors, fn
      {^field, {msg, opts}} ->
        Keyword.get(opts, :constraint) != nil and (message == nil or msg == message)

      _ ->
        false
    end)
  end

  defp get_default_role(workspace_id) do
    from(r in WorkspaceRole,
      where: r.workspace_id == ^workspace_id and r.is_default == true
    )
    |> Repo.one()
  end

  @max_accept_retries 3

  @spec accept_invitation(String.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def accept_invitation(token_hash, user_id, user_email) do
    accept_invitation_with_retry(token_hash, user_id, user_email, 0)
  end

  defp accept_invitation_with_retry(_token_hash, _user_id, _user_email, @max_accept_retries) do
    {:error, :serialization_failure}
  end

  defp accept_invitation_with_retry(token_hash, user_id, user_email, attempt) do
    case do_accept_invitation(token_hash, user_id, user_email) do
      {:error, :retry} ->
        accept_invitation_with_retry(token_hash, user_id, user_email, attempt + 1)

      {:error, :member_removed} ->
        accept_invitation_with_retry(token_hash, user_id, user_email, attempt + 1)

      other ->
        other
    end
  end

  defp do_accept_invitation(token_hash, user_id, user_email) do
    invitation = find_invitation_by_hash(token_hash)

    if is_nil(invitation) do
      {:error, :not_found}
    else
      existing_member = find_existing_member(invitation.workspace_id, user_id)

      if existing_member do
        handle_existing_member_acceptance(invitation, user_id, user_email)
      else
        attempt_new_member_acceptance(invitation, user_id, user_email)
      end
    end
  rescue
    e in Postgrex.Error ->
      case e.postgres.code do
        :serialization_failure -> {:error, :retry}
        :deadlock_detected -> {:error, :retry}
        _ -> reraise e, __STACKTRACE__
      end
  end

  defp find_invitation_by_hash(token_hash) do
    from(i in WorkspaceInvitation, where: i.token_hash == ^token_hash)
    |> Repo.one()
  end

  defp find_existing_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: wm
    )
    |> Repo.one()
  end

  defp handle_existing_member_acceptance(invitation, user_id, user_email) do
    Repo.transaction(fn ->
      workspace = lock_workspace_for_share(invitation.workspace_id)
      if is_nil(workspace), do: Repo.rollback(:not_found)

      member = lock_existing_member(invitation.workspace_id, user_id)

      fresh_invitation =
        from(i in WorkspaceInvitation,
          where: i.id == ^invitation.id,
          lock: "FOR SHARE"
        )
        |> Repo.one()

      if is_nil(fresh_invitation) do
        Repo.rollback(:not_found)
      else
        validate_and_accept_existing_member(member, fresh_invitation, user_email, workspace)
      end
    end)
    |> normalize_transaction_result()
  end

  defp lock_existing_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      lock: "FOR SHARE",
      select: wm
    )
    |> Repo.one()
  end

  defp validate_and_accept_existing_member(nil, _invitation, _user_email, _workspace) do
    Repo.rollback(:member_removed)
  end

  defp validate_and_accept_existing_member(_member, invitation, user_email, workspace) do
    case validate_existing_member_acceptance(invitation, user_email, workspace) do
      :ok -> build_acceptance_result(invitation, workspace)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp validate_existing_member_acceptance(invitation, user_email, workspace) do
    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, DateTime.utc_now()) != :gt ->
        {:error, :invitation_expired}

      invitation.invited_email != user_email ->
        {:error, :email_mismatch}

      workspace.needs_kek_rotation ->
        {:error, :kek_rotation_in_progress}

      invitation.kek_version < workspace.min_kek_version ->
        {:error, {:invitation_kek_outdated, invitation.workspace_id}}

      true ->
        :ok
    end
  end

  defp attempt_new_member_acceptance(invitation, user_id, user_email) do
    Repo.transaction(fn ->
      EctoSQL.query!(Repo, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", [])

      workspace = lock_workspace_for_share(invitation.workspace_id)
      if is_nil(workspace), do: Repo.rollback(:not_found)

      case execute_cte_acceptance(invitation, user_id, user_email, workspace) do
        {:ok, result} -> result
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  end

  defp execute_cte_acceptance(invitation, user_id, user_email, workspace) do
    now = DateTime.utc_now()
    min_kek = workspace.min_kek_version
    rotation_ok = not workspace.needs_kek_rotation

    updated_count =
      from(i in WorkspaceInvitation,
        where: i.id == ^invitation.id,
        where: i.workspace_id == ^invitation.workspace_id,
        where: is_nil(i.revoked_at),
        where: i.expires_at > ^now,
        where: i.is_used == false,
        where: i.invited_email == ^user_email,
        where: not is_nil(i.role_id),
        where: i.kek_version >= ^min_kek,
        where: ^rotation_ok
      )
      |> Repo.update_all(set: [is_used: true])
      |> elem(0)

    if updated_count == 1 do
      insert_new_member(invitation, user_id, user_email, workspace)
    else
      handle_cte_zero_rows(invitation, user_id, user_email, workspace)
    end
  end

  defp insert_new_member(invitation, user_id, user_email, workspace) do
    result =
      %WorkspaceMember{}
      |> WorkspaceMember.changeset(%{
        workspace_id: invitation.workspace_id,
        user_id: user_id,
        role_id: invitation.role_id,
        is_default: false,
        joined_at: DateTime.utc_now()
      })
      |> Repo.insert()

    case result do
      {:ok, member} ->
        broadcast_invitation_accepted(invitation.workspace_id, member.user_id)
        build_acceptance_result(invitation, workspace)

      {:error, changeset} ->
        if has_constraint_error?(changeset, :workspace_id, "has already been taken") do
          validate_and_return_existing_member_result(invitation, user_email, workspace)
        else
          handle_member_insert_fk_error(changeset)
        end
    end
  end

  defp validate_and_return_existing_member_result(invitation, user_email, workspace) do
    case validate_existing_member_acceptance(invitation, user_email, workspace) do
      :ok -> build_acceptance_result(invitation, workspace)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp handle_member_insert_fk_error(changeset) do
    cond do
      has_constraint_error?(changeset, :role_id) ->
        {:error, :invitation_role_deleted}

      has_constraint_error?(changeset, :workspace_id) ->
        {:error, :not_found}

      true ->
        {:error, :validation_error}
    end
  end

  defp handle_cte_zero_rows(invitation, user_id, user_email, workspace) do
    fresh_invitation = Repo.get(WorkspaceInvitation, invitation.id)

    if is_nil(fresh_invitation) do
      {:error, :not_found}
    else
      existing_member = lock_existing_member(invitation.workspace_id, user_id)

      if existing_member do
        validate_and_return_existing_member_result(fresh_invitation, user_email, workspace)
      else
        diagnose_acceptance_failure(fresh_invitation, user_email, workspace)
      end
    end
  end

  defp diagnose_acceptance_failure(invitation, user_email, workspace) do
    with :ok <- check_invitation_validity(invitation, user_email) do
      check_workspace_acceptance_state(invitation, workspace)
    end
  end

  defp check_invitation_validity(invitation, user_email) do
    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, DateTime.utc_now()) != :gt ->
        {:error, :invitation_expired}

      invitation.is_used ->
        {:error, :invitation_already_used}

      invitation.invited_email != user_email ->
        {:error, :email_mismatch}

      true ->
        :ok
    end
  end

  defp check_workspace_acceptance_state(invitation, workspace) do
    cond do
      workspace.needs_kek_rotation ->
        {:error, :kek_rotation_in_progress}

      invitation.kek_version < workspace.min_kek_version ->
        {:error, {:invitation_kek_outdated, invitation.workspace_id}}

      invitation.role_id == nil ->
        {:error, :invitation_role_deleted}

      true ->
        {:error, :not_found}
    end
  end

  defp broadcast_invitation_accepted(workspace_id, user_id) do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "workspace:#{workspace_id}",
      {:invitation_accepted, %{workspace_id: workspace_id, user_id: user_id}}
    )
  rescue
    _ -> :ok
  end

  defp build_acceptance_result(invitation, workspace) do
    role_name =
      case invitation.role_id do
        nil ->
          nil

        role_id ->
          case Repo.get(WorkspaceRole, role_id) do
            nil -> nil
            role -> role.name
          end
      end

    {:ok,
     %{
       workspace_id: invitation.workspace_id,
       workspace_name: workspace.name,
       role_name: role_name,
       invitation_id: invitation.id,
       encrypted_kek: invitation.encrypted_kek,
       kek_nonce: invitation.kek_nonce,
       kek_version: invitation.kek_version
     }}
  end

  @spec list_active_invitations(Ecto.UUID.t()) :: [map()]
  def list_active_invitations(workspace_id) do
    now = DateTime.utc_now()

    from(i in WorkspaceInvitation,
      join: w in Workspace,
      on: w.id == i.workspace_id,
      where:
        i.workspace_id == ^workspace_id and
          is_nil(i.revoked_at) and
          i.expires_at > ^now and
          i.is_used == false and
          not is_nil(i.role_id) and
          i.kek_version >= w.min_kek_version,
      left_join: r in WorkspaceRole,
      on: r.id == i.role_id,
      select: %{
        invitation_id: i.id,
        workspace_id: i.workspace_id,
        token_prefix: i.token_prefix,
        role_id: i.role_id,
        role_name: r.name,
        invited_by: i.invited_by,
        invited_email: i.invited_email,
        kek_version: i.kek_version,
        is_used: i.is_used,
        expires_at: i.expires_at,
        created_at: i.created_at
      },
      order_by: [desc: i.created_at]
    )
    |> Repo.all()
  end

  @spec revoke_invitation(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, WorkspaceInvitation.t()} | {:error, :not_found}
  def revoke_invitation(workspace_id, invitation_id) do
    Repo.transaction(fn ->
      case Repo.one(
             from(i in WorkspaceInvitation,
               where:
                 i.id == ^invitation_id and
                   i.workspace_id == ^workspace_id and
                   is_nil(i.revoked_at),
               lock: "FOR UPDATE"
             )
           ) do
        nil ->
          Repo.rollback(:not_found)

        invitation ->
          now = DateTime.utc_now()

          {1, _} =
            from(i in WorkspaceInvitation, where: i.id == ^invitation.id)
            |> Repo.update_all(set: [revoked_at: now])

          %{invitation | revoked_at: now}
      end
    end)
  end

  @spec revoke_invitations_for_email(Ecto.UUID.t(), String.t()) :: non_neg_integer()
  def revoke_invitations_for_email(workspace_id, email) do
    now = DateTime.utc_now()

    {count, _} =
      from(i in WorkspaceInvitation,
        where:
          i.workspace_id == ^workspace_id and
            i.invited_email == ^email and
            is_nil(i.revoked_at) and
            i.is_used == false
      )
      |> Repo.update_all(set: [revoked_at: now])

    count
  end

  @spec revoke_all_active_invitations([Ecto.UUID.t()]) :: non_neg_integer()
  def revoke_all_active_invitations([]), do: 0

  def revoke_all_active_invitations(workspace_ids) do
    now = DateTime.utc_now()

    {count, _} =
      from(i in WorkspaceInvitation,
        where:
          i.workspace_id in ^workspace_ids and
            is_nil(i.revoked_at) and
            i.expires_at > ^now and
            i.is_used == false
      )
      |> Repo.update_all(set: [revoked_at: now])

    count
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp generate_slug(name) do
    base =
      name
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    base = if base == "", do: "workspace", else: base

    suffix =
      :crypto.strong_rand_bytes(4)
      |> Base.url_encode64(padding: false)
      |> String.downcase()
      |> String.replace("_", "-")
      |> String.replace(~r/-+/, "-")
      |> String.trim("-")

    "#{base}-#{suffix}"
  end
end
