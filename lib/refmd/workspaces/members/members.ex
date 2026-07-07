defmodule RefMD.Workspaces.Members do
  @moduledoc false

  require Logger

  import Ecto.Query

  alias RefMD.{Devices, Encryption}
  alias RefMD.Repo

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  alias RefMD.Workspaces.Guests, as: WGuests
  alias RefMD.Workspaces.Invitations, as: WInvitations

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

  @spec member_permission_granted?(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) :: boolean()
  def member_permission_granted?(workspace_id, user_id, permission) when is_binary(permission) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      left_join: p in WorkspaceRolePermission,
      on: p.role_id == r.id and p.permission == ^permission,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: %{
        base_role: r.base_role,
        catalog_version: r.catalog_version,
        permission: p.permission,
        granted: p.granted
      },
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil ->
        false

      row ->
        role = %{
          base_role: row.base_role,
          catalog_version: row.catalog_version,
          permissions: permission_override(row)
        }

        RefMD.Workspaces.permission_granted?(role, permission)
    end
  end

  defp permission_override(%{permission: permission, granted: granted})
       when is_binary(permission) and is_boolean(granted),
       do: [%{permission: permission, granted: granted}]

  defp permission_override(_row), do: []

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

  @spec change_member_role(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, WorkspaceMember.t()} | {:error, atom()}
  def change_member_role(workspace_id, target_user_id, new_role_id, actor_user_id, key_directory) do
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
        append_member_role_change_key_directory!(
          workspace_id,
          target_user_id,
          ctx.target_role,
          ctx.new_role,
          key_directory
        )

        do_change_role(workspace_id, target_user_id, new_role_id)
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec remove_member(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def remove_member(workspace_id, target_user_id, actor_user_id, key_directory) do
    result =
      Repo.transaction(fn ->
        lock_workspace_row(workspace_id)
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
            append_member_removal_key_directory!(workspace_id, target_user_id, key_directory)

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

  # ── Private Helpers ─────────────────────────────

  defp validate_role_change(%{target_role: nil}, _workspace_id), do: {:error, :target_not_member}
  defp validate_role_change(%{new_role: nil}, _workspace_id), do: {:error, :invalid_role}

  defp validate_role_change(ctx, workspace_id) do
    validate_role_change_rules(ctx, workspace_id) ||
      RefMD.Workspaces.validate_role_assignment(ctx.actor_role, ctx.new_role)
  end

  defp validate_role_change_rules(ctx, workspace_id) do
    [
      validate_role_workspace(ctx, workspace_id),
      validate_guest_role_change(ctx),
      validate_owner_role_change(ctx),
      validate_last_owner_role_change(ctx)
    ]
    |> Enum.find(& &1)
  end

  defp validate_role_workspace(ctx, workspace_id) do
    if ctx.new_role.workspace_id != workspace_id, do: {:error, :invalid_role}
  end

  defp validate_guest_role_change(ctx) do
    if ctx.target_role.base_role == "guest" or ctx.new_role.base_role == "guest",
      do: {:error, :guest_role_immutable}
  end

  defp validate_owner_role_change(ctx) do
    if ctx.target_role.base_role == "owner" and ctx.actor_role.base_role != "owner",
      do: {:error, :cannot_modify_owner}
  end

  defp validate_last_owner_role_change(ctx) do
    if ctx.target_role.base_role == "owner" and ctx.new_role.base_role != "owner" and
         ctx.owner_count <= 1,
       do: {:error, :last_owner}
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
    WGuests.revoke_guest_grants(workspace_id, target_user_id)

    case get_user_email(target_user_id) do
      nil -> :ok
      email -> WInvitations.revoke_invitations_for_email(workspace_id, email)
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

    RefMD.Workspaces.mark_dek_rotation_needed([workspace_id])
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

  defp check_rbac_permission(nil, _permission), do: {:error, :actor_not_member}

  defp check_rbac_permission(role, permission) do
    perms = RefMD.Workspaces.effective_permissions(role)
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

  defp lock_workspace_row(workspace_id) do
    from(w in Workspace,
      where: w.id == ^workspace_id,
      lock: "FOR UPDATE",
      select: w.id
    )
    |> Repo.one!()
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

  defp append_member_role_change_key_directory!(
         workspace_id,
         target_user_id,
         previous_role,
         new_role,
         %{
           workspace_events: workspace_events,
           workspace_checkpoint: workspace_checkpoint
         }
       )
       when is_list(workspace_events) and is_map(workspace_checkpoint) do
    assert_member_role_change_append!(
      workspace_events,
      workspace_id,
      target_user_id,
      previous_role,
      new_role
    )

    Encryption.append_workspace_key_directory!(
      workspace_id,
      workspace_events,
      workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp append_member_role_change_key_directory!(_, _, _, _, _),
    do: Repo.rollback(:missing_key_directory)

  defp assert_member_role_change_append!(
         [%{"payload" => %{"event_type" => "member_role_changed", "body" => body}}],
         workspace_id,
         target_user_id,
         previous_role,
         new_role
       ) do
    expected = %{
      "workspace_id" => workspace_id,
      "user_id" => target_user_id,
      "previous_role_id" => previous_role.id,
      "previous_base_role" => previous_role.base_role,
      "role_id" => new_role.id,
      "base_role" => new_role.base_role
    }

    unless Map.take(body, Map.keys(expected)) == expected do
      raise ArgumentError, "key_directory_member_role_changed_event_mismatch"
    end
  end

  defp assert_member_role_change_append!(_, _, _, _, _),
    do: raise(ArgumentError, "key_directory_member_role_changed_event_mismatch")

  defp append_member_removal_key_directory!(
         workspace_id,
         target_user_id,
         %{
           workspace_events: workspace_events,
           workspace_checkpoint: workspace_checkpoint
         }
       )
       when is_list(workspace_events) and is_map(workspace_checkpoint) do
    assert_member_removal_append!(workspace_events, workspace_id, target_user_id)
    assert_member_removal_revocations!(workspace_events, workspace_id, target_user_id)

    Encryption.append_workspace_key_directory!(
      workspace_id,
      workspace_events,
      workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp append_member_removal_key_directory!(_, _, _), do: Repo.rollback(:missing_key_directory)

  defp assert_member_removal_append!(
         [
           %{"payload" => %{"event_type" => "member_removed", "body" => body}} | revocation_events
         ],
         workspace_id,
         target_user_id
       ) do
    expected_member_removed = %{
      "workspace_id" => workspace_id,
      "user_id" => target_user_id
    }

    unless Map.take(body, ["workspace_id", "user_id"]) == expected_member_removed do
      raise ArgumentError, "key_directory_member_removed_event_mismatch"
    end

    actual_revocations =
      revocation_events
      |> Enum.map(fn %{"payload" => %{"event_type" => type, "body" => body}} ->
        {type, body["key_id"], body["reason"]}
      end)
      |> Enum.sort()

    valid_types = ["signing_key_revoked", "encryption_key_revoked"]

    if Enum.all?(actual_revocations, fn {type, key_id, reason} ->
         type in valid_types and is_binary(key_id) and reason == "member_removed"
       end),
       do: :ok,
       else: raise(ArgumentError, "key_directory_member_key_revocation_mismatch")
  end

  defp assert_member_removal_append!(_, _, _),
    do: raise(ArgumentError, "key_directory_member_removed_event_mismatch")

  defp assert_member_removal_revocations!(
         [
           %{"payload" => %{"event_type" => "member_removed"}} | revocation_events
         ],
         workspace_id,
         target_user_id
       ) do
    actual =
      revocation_events
      |> Enum.map(fn %{"payload" => %{"event_type" => type, "body" => body}} ->
        {type, body["key_id"]}
      end)
      |> Enum.sort()

    expected =
      target_user_id
      |> Devices.get_user_devices(include_revoked: false)
      |> Enum.filter(&workspace_checkpoint_device_keys_present?(workspace_id, &1))
      |> Enum.flat_map(fn device ->
        [
          {"signing_key_revoked", device.signing_key_id},
          {"encryption_key_revoked", device.encryption_key_id}
        ]
      end)
      |> Enum.sort()

    if actual == expected do
      :ok
    else
      raise ArgumentError, "key_directory_member_key_revocation_mismatch"
    end
  end

  defp assert_member_removal_revocations!(_, _, _),
    do: raise(ArgumentError, "key_directory_member_key_revocation_mismatch")

  defp workspace_checkpoint_device_keys_present?(workspace_id, device) do
    match?(
      {:ok, _},
      Encryption.active_workspace_key_material_in_current_checkpoint(
        workspace_id,
        device.signing_key_id
      )
    ) and
      match?(
        {:ok, _},
        Encryption.active_workspace_key_material_in_current_checkpoint(
          workspace_id,
          device.encryption_key_id
        )
      )
  end

  defp do_change_role(workspace_id, user_id, new_role_id) do
    {1, _} =
      from(wm in WorkspaceMember,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
      )
      |> Repo.update_all(set: [role_id: new_role_id], inc: [permission_version: 1])

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
end
