defmodule RefMD.Workspaces.Members do
  @moduledoc false

  import Ecto.Query

  alias RefMD.{Devices, Encryption}
  alias RefMD.Repo
  alias RefMD.Workspaces.KekRotation

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  alias RefMD.Workspaces.Guests, as: WGuests
  alias RefMD.Workspaces.Invitations, as: WInvitations

  def list_workspace_member_user_ids(workspace_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id,
      select: wm.user_id
    )
    |> Repo.all()
  end

  def get_workspace_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
    )
    |> Repo.one()
  end

  def get_member_role(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: r.base_role
    )
    |> Repo.one()
  end

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
        permission_version: wm.permission_version,
        joined_at: wm.joined_at
      },
      order_by: [asc: wm.joined_at]
    )
    |> Repo.all()
  end

  def change_member_role(workspace_id, target_user_id, new_role_id, actor_user_id, key_directory) do
    Repo.transaction(fn ->
      owner_rows = lock_owner_rows(workspace_id)
      target_member = lock_member!(workspace_id, target_user_id)

      new_role =
        case Repo.get(WorkspaceRole, new_role_id) do
          nil -> nil
          r -> Repo.preload(r, :permissions)
        end

      ctx = %{
        actor_role: fetch_role_for_user(workspace_id, actor_user_id),
        target_role: fetch_role_for_user(workspace_id, target_user_id),
        new_role: new_role,
        target_member: target_member,
        owner_count: count_owners(owner_rows)
      }

      with :ok <- check_rbac_permission(ctx.actor_role, "member:change_role"),
           :ok <- validate_role_change(ctx, workspace_id) do
        append_member_role_change_key_directory!(
          workspace_id,
          target_user_id,
          ctx.target_role,
          ctx.new_role,
          ctx.target_member.permission_version + 1,
          key_directory
        )

        previous_permissions = effective_permissions(ctx.target_role)
        effective_permissions = effective_permissions(ctx.new_role)
        permission_loss? = not MapSet.subset?(previous_permissions, effective_permissions)

        read_loss? =
          MapSet.member?(previous_permissions, "document:read") and
            not MapSet.member?(effective_permissions, "document:read")

        member = do_change_role(workspace_id, target_user_id, new_role_id)

        maybe_mark_role_change_rotation!(
          read_loss?,
          workspace_id,
          target_user_id,
          actor_user_id
        )

        %{member: member, permission_loss?: permission_loss?}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, %{member: member, permission_loss?: permission_loss?}} ->
        if permission_loss?, do: disconnect_member_sessions(target_user_id)
        {:ok, member}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def remove_member(workspace_id, target_user_id, actor_user_id, key_directory) do
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

          KekRotation.mark_membership_rotation_needed!(
            workspace_id,
            rotation_initiator(workspace_id, target_user_id, actor_user_id)
          )

          member

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
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
    KekRotation.next_rotation_initiator(workspace_id)
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

  defp rotation_initiator(workspace_id, target_user_id, actor_user_id) do
    if target_user_id == actor_user_id do
      find_rotation_initiator(workspace_id)
    else
      actor_user_id
    end
  end

  defp maybe_mark_role_change_rotation!(false, _workspace_id, _target_user_id, _actor_user_id),
    do: :ok

  defp maybe_mark_role_change_rotation!(true, workspace_id, target_user_id, actor_user_id) do
    KekRotation.mark_membership_rotation_needed!(
      workspace_id,
      rotation_initiator(workspace_id, target_user_id, actor_user_id)
    )
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

  defp lock_member!(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
    |> case do
      nil -> Repo.rollback(:target_not_member)
      member -> member
    end
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
         permission_version,
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
      new_role,
      permission_version
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

  defp append_member_role_change_key_directory!(_, _, _, _, _, _),
    do: Repo.rollback(:missing_key_directory)

  defp assert_member_role_change_append!(
         [%{"payload" => %{"event_type" => "member_role_changed", "body" => body}}],
         workspace_id,
         target_user_id,
         previous_role,
         new_role,
         permission_version
       ) do
    expected = %{
      "workspace_id" => workspace_id,
      "user_id" => target_user_id,
      "previous_role_id" => previous_role.id,
      "previous_base_role" => previous_role.base_role,
      "previous_effective_permissions" => canonical_effective_permissions(previous_role),
      "role_id" => new_role.id,
      "base_role" => new_role.base_role,
      "effective_permissions" => canonical_effective_permissions(new_role),
      "permission_version" => permission_version
    }

    unless Map.take(body, Map.keys(expected)) == expected do
      raise ArgumentError, "key_directory_member_role_changed_event_mismatch"
    end
  end

  defp assert_member_role_change_append!(_, _, _, _, _, _),
    do: raise(ArgumentError, "key_directory_member_role_changed_event_mismatch")

  defp canonical_effective_permissions(role),
    do: role |> effective_permissions() |> MapSet.to_list() |> Enum.sort()

  defp effective_permissions(role), do: RefMD.Workspaces.effective_permissions(role)

  def disconnect_member_sessions(user_id) do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "user_socket:#{user_id}",
      %Phoenix.Socket.Broadcast{
        topic: "user_socket:#{user_id}",
        event: "disconnect",
        payload: %{}
      }
    )
  end

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
