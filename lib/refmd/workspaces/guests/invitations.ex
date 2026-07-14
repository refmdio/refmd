defmodule RefMD.Workspaces.Guests.Invitations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Repo
  alias RefMD.Sharing.{Share, ShareKey}
  alias RefMD.Users
  alias RefMD.Workspaces.Invitations.KeyDirectory

  alias RefMD.Workspaces.{
    GuestInvitation,
    Workspace,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  @transaction_retry_max 3

  def create_guest_invitation(attrs) do
    with_transaction_retry(fn ->
      workspace =
        from(w in Workspace, where: w.id == ^attrs.workspace_id, lock: "FOR UPDATE")
        |> Repo.one()

      with %Workspace{} <- workspace,
           :ok <- validate_workspace_settings(workspace),
           :ok <- validate_invitation_key_context(workspace, attrs),
           {:ok, actor_role} <- lock_actor_role(attrs.workspace_id, attrs.invited_by),
           :ok <- validate_guest_role(actor_role),
           :ok <- validate_recipient_delivery_binding(attrs),
           {:ok, guest_role} <- get_guest_workspace_role(workspace.id),
           :ok <- validate_guest_role_escalation(actor_role, guest_role, attrs.permission),
           :ok <- validate_scope_kind(attrs),
           {:ok, invitation} <- insert_guest_invitation(attrs),
           :ok <-
             KeyDirectory.append_if_present(attrs[:key_directory], %{
               kind: :guest_invitation_created,
               workspace_id: invitation.workspace_id,
               actor_user_id: attrs.invited_by,
               actor_device_id: attrs[:actor_device_id],
               invitation: invitation
             }) do
        invitation
      else
        nil -> Repo.rollback(:workspace_not_found)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def list_guest_invitations(workspace_id) do
    from(i in GuestInvitation,
      where: i.workspace_id == ^workspace_id and is_nil(i.revoked_at),
      select: %{
        invitation_id: i.id,
        workspace_id: i.workspace_id,
        token_prefix: i.token_prefix,
        scope_kind: i.scope_kind,
        scope_id: i.scope_id,
        share_id: i.share_id,
        permission: i.permission,
        invited_email: i.invited_email,
        delivery_mode: i.delivery_mode,
        recipient_user_id: i.recipient_user_id,
        recipient_device_ids: i.recipient_device_ids,
        invited_by: i.invited_by,
        kek_version: i.kek_version,
        share_key_version: i.share_key_version,
        dek_version: i.dek_version,
        bootstrap_key_commitment: i.bootstrap_key_commitment,
        encrypted_bootstrap_package: i.encrypted_bootstrap_package,
        bootstrap_package_hash: i.bootstrap_package_hash,
        bootstrap_package_key_recipient_wrap: i.bootstrap_package_key_recipient_wrap,
        bootstrap_package_key_maintenance_wrap: i.bootstrap_package_key_maintenance_wrap,
        bootstrap_suite_id: i.bootstrap_suite_id,
        capability_context_hash: i.capability_context_hash,
        max_redemptions: i.max_redemptions,
        redemption_count: i.redemption_count,
        expires_at: i.expires_at,
        created_at: i.created_at,
        revoked_at: i.revoked_at
      },
      order_by: [desc: i.created_at]
    )
    |> Repo.all()
  end

  def delete_expired_guest_invitations(now \\ DateTime.utc_now()) do
    {count, _} =
      from(i in GuestInvitation,
        where:
          i.expires_at <= ^now and
            i.redemption_count == 0
      )
      |> Repo.delete_all()

    count
  end

  def revoke_guest_invitation(workspace_id, invitation_id, actor_user_id) do
    revoke_guest_invitation(workspace_id, invitation_id, actor_user_id, nil)
  end

  def revoke_guest_invitation(workspace_id, invitation_id, actor_user_id, key_directory) do
    with_transaction_retry(fn ->
      invitation =
        from(i in GuestInvitation,
          where:
            i.id == ^invitation_id and
              i.workspace_id == ^workspace_id and
              is_nil(i.revoked_at),
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      workspace =
        from(w in Workspace, where: w.id == ^workspace_id, lock: "FOR UPDATE")
        |> Repo.one()

      with %GuestInvitation{} <- invitation,
           %Workspace{} <- workspace,
           :ok <- validate_workspace_settings(workspace),
           {:ok, actor_role} <- lock_actor_role(workspace_id, actor_user_id),
           :ok <- validate_guest_role(actor_role) do
        now = DateTime.utc_now()

        {1, _} =
          from(i in GuestInvitation, where: i.id == ^invitation.id)
          |> Repo.update_all(set: [revoked_at: now])

        revoked = %{invitation | revoked_at: now}

        KeyDirectory.append_if_present(key_directory, %{
          kind: :guest_invitation_revoked,
          workspace_id: workspace_id,
          actor_user_id: actor_user_id,
          actor_device_id: Map.get(key_directory || %{}, :actor_device_id),
          invitation: revoked
        })

        revoked
      else
        nil -> Repo.rollback(:not_found)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def guest_invites_enabled?(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, select: w.guest_invites_enabled)
    |> Repo.one()
    |> Kernel.==(true)
  end

  def revoke_all_active_guest_invitations([]), do: 0

  def revoke_all_active_guest_invitations(workspace_ids) do
    now = DateTime.utc_now()

    {count, _} =
      from(i in GuestInvitation,
        where:
          i.workspace_id in ^workspace_ids and
            is_nil(i.revoked_at) and
            i.expires_at > ^now
      )
      |> Repo.update_all(set: [revoked_at: now])

    count
  end

  defp validate_workspace_settings(%Workspace{guest_invites_enabled: true}), do: :ok
  defp validate_workspace_settings(_workspace), do: {:error, :guest_invites_disabled}

  defp validate_recipient_delivery_binding(attrs) do
    Users.validate_invitation_delivery_binding(
      attrs[:invited_email],
      attrs.delivery_mode,
      attrs[:recipient_user_id],
      attrs[:recipient_device_ids] || []
    )
  end

  defp validate_invitation_key_context(
         %Workspace{current_kek_version: 0},
         %{scope_kind: "workspace"}
       ),
       do: {:error, :encryption_setup_incomplete}

  defp validate_invitation_key_context(
         %Workspace{} = workspace,
         %{scope_kind: "workspace"} = attrs
       ) do
    cond do
      RotationPolicy.kek_overdue?(workspace) -> {:error, :kek_rotation_in_progress}
      attrs.kek_version != workspace.current_kek_version -> {:error, :kek_version_mismatch}
      attrs[:share_id] != nil -> {:error, :invalid_key_version_context}
      attrs[:share_key_version] != nil -> {:error, :invalid_key_version_context}
      attrs[:dek_version] != nil -> {:error, :invalid_key_version_context}
      true -> :ok
    end
  end

  defp validate_invitation_key_context(%Workspace{} = workspace, attrs)
       when attrs.scope_kind in ["document", "folder", "share"] do
    target =
      from(s in Share,
        join: d in Document,
        on: d.id == s.document_id,
        join: sk in ShareKey,
        on: sk.share_id == s.id,
        where:
          s.id == ^attrs.share_id and d.workspace_id == ^workspace.id and
            is_nil(d.archived_at),
        lock: "FOR SHARE",
        select: %{share: s, document: d, share_key: sk},
        limit: 1
      )
      |> Repo.one()

    with %{share: share, document: document, share_key: share_key} <- target,
         true <- attrs.kek_version == nil,
         true <- attrs.share_key_version == share_key.key_version,
         true <- attrs.dek_version == share_key.key_version,
         true <- attrs.permission == share.permission,
         true <- scoped_share_matches?(attrs, share, document) do
      :ok
    else
      nil -> {:error, :share_not_found}
      _ -> {:error, :invalid_key_version_context}
    end
  end

  defp validate_invitation_key_context(_workspace, _attrs),
    do: {:error, :invalid_key_version_context}

  defp scoped_share_matches?(%{scope_kind: "share", scope_id: scope_id}, share, _document),
    do: scope_id == share.id

  defp scoped_share_matches?(%{scope_kind: scope_kind, scope_id: scope_id}, share, document)
       when scope_kind in ["document", "folder"],
       do: scope_id == document.id and scope_kind == share.scope

  defp scoped_share_matches?(_attrs, _share, _document), do: false

  defp validate_guest_role(role) do
    if role |> RefMD.Workspaces.effective_permissions() |> MapSet.member?("guest:invite"),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp validate_guest_role_escalation(actor_role, target_role, invitation_permission) do
    actor_permissions = RefMD.Workspaces.effective_permissions(actor_role)

    target_permissions =
      effective_guest_invitation_permissions(target_role, invitation_permission)

    if MapSet.subset?(target_permissions, actor_permissions) do
      :ok
    else
      {:error, :permission_escalation}
    end
  end

  defp effective_guest_invitation_permissions(target_role, "view") do
    target_role
    |> effective_guest_invitation_permissions("edit")
    |> MapSet.intersection(MapSet.new(["document:read"]))
  end

  defp effective_guest_invitation_permissions(target_role, "edit") do
    target_role
    |> RefMD.Workspaces.effective_permissions()
    |> MapSet.intersection(MapSet.new(["document:read", "document:write", "document:archive"]))
  end

  defp get_guest_workspace_role(workspace_id), do: get_builtin_role(workspace_id, "guest")

  defp get_builtin_role(workspace_id, base_role) do
    role =
      from(r in WorkspaceRole,
        where:
          r.workspace_id == ^workspace_id and
            r.base_role == ^base_role and
            is_nil(r.catalog_version),
        preload: [:permissions],
        limit: 1
      )
      |> Repo.one()

    if role, do: {:ok, role}, else: {:error, :no_guest_role}
  end

  defp validate_scope_kind(%{scope_kind: "workspace"} = attrs) do
    if is_nil(attrs[:scope_id]) and is_nil(attrs[:share_id]),
      do: :ok,
      else: {:error, :invalid_scope_kind}
  end

  defp validate_scope_kind(%{scope_kind: scope_kind, scope_id: scope_id, share_id: share_id})
       when scope_kind in ["document", "folder", "share"] and is_binary(scope_id) and
              is_binary(share_id),
       do: :ok

  defp validate_scope_kind(_attrs), do: {:error, :invalid_scope_kind}

  defp insert_guest_invitation(attrs) do
    now = DateTime.utc_now()

    %GuestInvitation{created_at: now}
    |> GuestInvitation.changeset(%{
      id: attrs.invitation_id,
      workspace_id: attrs.workspace_id,
      token_hash: attrs.token_hash,
      token_prefix: attrs.token_prefix,
      scope_kind: attrs.scope_kind,
      scope_id: attrs.scope_id,
      share_id: attrs[:share_id],
      permission: attrs.permission,
      invited_email: attrs[:invited_email],
      delivery_mode: attrs.delivery_mode,
      recipient_user_id: attrs[:recipient_user_id],
      recipient_device_ids: attrs[:recipient_device_ids] || [],
      kek_version: attrs.kek_version,
      share_key_version: attrs[:share_key_version],
      dek_version: attrs[:dek_version],
      bootstrap_key_commitment: attrs.bootstrap_key_commitment,
      encrypted_bootstrap_package: attrs.encrypted_bootstrap_package,
      bootstrap_package_hash: attrs.bootstrap_package_hash,
      bootstrap_package_key_recipient_wrap: attrs.bootstrap_package_key_recipient_wrap,
      bootstrap_package_key_maintenance_wrap: attrs[:bootstrap_package_key_maintenance_wrap],
      bootstrap_suite_id: attrs.bootstrap_suite_id,
      capability_context_hash: attrs.capability_context_hash,
      max_redemptions: attrs.max_redemptions || 1,
      redemption_count: 0,
      invited_by: attrs.invited_by,
      expires_at: attrs.expires_at || DateTime.add(now, 7 * 86_400, :second)
    })
    |> Repo.insert()
    |> normalize_insert_error()
  end

  defp normalize_insert_error({:ok, invitation}), do: {:ok, invitation}

  defp normalize_insert_error({:error, changeset}) do
    cond do
      unique_constraint_error?(changeset, :token_hash) ->
        {:error, :token_hash_already_exists}

      unique_constraint_error?(changeset, :id) ->
        {:error, :id_already_exists}

      foreign_constraint_error?(changeset, :workspace_id) ->
        {:error, :workspace_not_found}

      foreign_constraint_error?(changeset, :scope_id) ->
        {:error, :invalid_scope}

      foreign_constraint_error?(changeset, :share_id) ->
        {:error, :share_not_found}

      true ->
        {:error, changeset}
    end
  end

  defp lock_actor_role(workspace_id, user_id) do
    role =
      from(m in WorkspaceMember,
        join: r in WorkspaceRole,
        on: r.id == m.role_id,
        where: m.workspace_id == ^workspace_id and m.user_id == ^user_id,
        lock: "FOR SHARE",
        select: r,
        limit: 1
      )
      |> Repo.one()

    case role do
      nil ->
        {:error, :permission_denied}

      role ->
        permissions =
          from(p in WorkspaceRolePermission,
            where: p.role_id == ^role.id,
            lock: "FOR SHARE"
          )
          |> Repo.all()

        {:ok, %{role | permissions: permissions}}
    end
  end

  defp with_transaction_retry(fun, attempt \\ 1) do
    Repo.transaction(fun, isolation: :serializable)
  rescue
    e in Postgrex.Error ->
      retryable? =
        e.postgres != nil and
          e.postgres.code in [
            "40P01",
            "40001",
            :deadlock_detected,
            :serialization_failure
          ]

      if retryable? and attempt < @transaction_retry_max do
        Process.sleep(Enum.random(5..25))
        with_transaction_retry(fun, attempt + 1)
      else
        if retryable? do
          {:error, :serialization_failure}
        else
          reraise e, __STACKTRACE__
        end
      end
  end

  defp unique_constraint_error?(changeset, field) do
    Enum.any?(changeset.errors, fn {error_field, {_msg, meta}} ->
      error_field == field and meta[:constraint] == :unique
    end)
  end

  defp foreign_constraint_error?(changeset, field) do
    Enum.any?(changeset.errors, fn {error_field, {_msg, meta}} ->
      error_field == field and meta[:constraint] == :foreign
    end)
  end
end
