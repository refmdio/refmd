defmodule RefMD.Workspaces.Members do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Workspaces.KekRotation

  alias RefMD.Workspaces.{
    GuestInvitation,
    InvitationDeliveryAttempt,
    Workspace,
    WorkspaceInvitation,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  alias RefMD.Workspaces.Guests, as: WGuests

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

  def prepare_role_change!(workspace_id, target_user_id, new_role_id, actor_user_id) do
    owner_rows = lock_owner_rows(workspace_id)
    target_member = lock_member!(workspace_id, target_user_id)

    new_role =
      case Repo.get(WorkspaceRole, new_role_id) do
        nil -> nil
        role -> Repo.preload(role, :permissions)
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
      ctx
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  def apply_role_change!(workspace_id, target_user_id, new_role_id, actor_user_id) do
    ctx = prepare_role_change!(workspace_id, target_user_id, new_role_id, actor_user_id)
    previous_permissions = effective_permissions(ctx.target_role)
    next_permissions = effective_permissions(ctx.new_role)
    permission_loss? = not MapSet.subset?(previous_permissions, next_permissions)

    member = do_change_role(workspace_id, target_user_id, new_role_id)
    %{member: member, permission_loss?: permission_loss?}
  end

  def prepare_removal!(workspace_id, target_user_id, actor_user_id) do
    workspace = lock_workspace_row(workspace_id)
    owner_rows = lock_owner_rows(workspace_id)
    target_role = fetch_role_for_user(workspace_id, target_user_id)
    documents = lock_workspace_documents(workspace_id)

    {workspace_invitations, guest_invitations} =
      lock_removal_invitations(workspace_id, target_user_id)

    case validate_removal(workspace_id, target_user_id, actor_user_id, target_role, owner_rows) do
      :ok ->
        %{
          target_role: target_role,
          owner_user_ids: owner_rows,
          workspace: workspace,
          documents: documents,
          workspace_invitations: workspace_invitations,
          guest_invitations: guest_invitations
        }

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  def apply_removal!(workspace_id, target_user_id, actor_user_id) do
    ctx = prepare_removal!(workspace_id, target_user_id, actor_user_id)
    member = do_remove_member(workspace_id, target_user_id)
    revoke_removal_invitations!(ctx)
    WGuests.revoke_guest_grants(workspace_id, target_user_id)

    KekRotation.mark_membership_rotation_needed!(
      workspace_id,
      rotation_initiator(workspace_id, target_user_id, actor_user_id)
    )

    member
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

  defp lock_removal_invitations(workspace_id, target_user_id) do
    now = DateTime.utc_now()
    target_email = Repo.get!(RefMD.Users.User, target_user_id).email
    dependent_contexts = removal_invitation_contexts(workspace_id, target_user_id)

    {
      lock_workspace_removal_invitations(
        workspace_id,
        target_user_id,
        target_email,
        now,
        context_ids(dependent_contexts, "workspace_invitation")
      ),
      lock_guest_removal_invitations(
        workspace_id,
        target_user_id,
        target_email,
        now,
        context_ids(dependent_contexts, "guest_invitation")
      )
    }
  end

  defp removal_invitation_contexts(workspace_id, target_user_id) do
    target_device_ids =
      from(device in RefMD.Devices.Device,
        where: device.user_id == ^target_user_id,
        select: device.id
      )
      |> Repo.all()

    from(attempt in InvitationDeliveryAttempt,
      where:
        attempt.workspace_id == ^workspace_id and
          attempt.recipient_device_id in ^target_device_ids and
          attempt.status in ["pending", "approved"],
      select: {attempt.context_kind, attempt.context_id}
    )
    |> Repo.all()
  end

  defp lock_workspace_removal_invitations(
         workspace_id,
         target_user_id,
         target_email,
         now,
         context_ids
       ) do
    from(invitation in WorkspaceInvitation,
      where:
        invitation.workspace_id == ^workspace_id and is_nil(invitation.revoked_at) and
          invitation.is_used == false and invitation.expires_at > ^now and
          (invitation.invited_by == ^target_user_id or
             invitation.recipient_user_id == ^target_user_id or
             invitation.invited_email == ^target_email or invitation.id in ^context_ids),
      order_by: [asc: invitation.id],
      lock: "FOR UPDATE"
    )
    |> Repo.all()
  end

  defp lock_guest_removal_invitations(
         workspace_id,
         target_user_id,
         target_email,
         now,
         context_ids
       ) do
    from(invitation in GuestInvitation,
      where:
        invitation.workspace_id == ^workspace_id and is_nil(invitation.revoked_at) and
          invitation.redemption_count < invitation.max_redemptions and
          invitation.expires_at > ^now and
          (invitation.invited_by == ^target_user_id or
             invitation.recipient_user_id == ^target_user_id or
             invitation.invited_email == ^target_email or invitation.id in ^context_ids),
      order_by: [asc: invitation.id],
      lock: "FOR UPDATE"
    )
    |> Repo.all()
  end

  defp context_ids(contexts, kind) do
    for {^kind, context_id} <- contexts, do: context_id
  end

  defp revoke_removal_invitations!(ctx) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    workspace_ids = Enum.map(ctx.workspace_invitations, & &1.id)
    guest_ids = Enum.map(ctx.guest_invitations, & &1.id)

    from(invitation in WorkspaceInvitation, where: invitation.id in ^workspace_ids)
    |> Repo.update_all(set: [revoked_at: now])

    from(invitation in GuestInvitation, where: invitation.id in ^guest_ids)
    |> Repo.update_all(set: [revoked_at: now])
  end

  defp rotation_initiator(workspace_id, target_user_id, actor_user_id) do
    if target_user_id == actor_user_id do
      find_rotation_initiator(workspace_id)
    else
      actor_user_id
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
      lock: "FOR UPDATE"
    )
    |> Repo.one!()
  end

  defp lock_workspace_documents(workspace_id) do
    from(document in Document,
      where: document.workspace_id == ^workspace_id,
      order_by: [asc: document.id],
      lock: "FOR UPDATE"
    )
    |> Repo.all()
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
end
