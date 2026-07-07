defmodule RefMD.Workspaces.Guests.Invitations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Sharing.Share
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
           :ok <- validate_workspace_crypto_state(workspace, attrs.kek_version),
           {:ok, actor_role} <- lock_actor_role(attrs.workspace_id, attrs.invited_by),
           :ok <- validate_guest_role(actor_role),
           {:ok, guest_role} <- get_guest_workspace_role(workspace.id),
           :ok <- validate_guest_role_escalation(actor_role, guest_role, attrs.permission),
           :ok <-
             validate_scope_kind(
               attrs.workspace_id,
               attrs.scope_kind,
               attrs.scope_id
             ),
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
        permission: i.permission,
        invited_by: i.invited_by,
        kek_version: i.kek_version,
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

  defp validate_workspace_crypto_state(%Workspace{needs_kek_rotation: true}, _kek_version),
    do: {:error, :kek_rotation_in_progress}

  defp validate_workspace_crypto_state(%Workspace{current_kek_version: 0}, _kek_version),
    do: {:error, :encryption_setup_incomplete}

  defp validate_workspace_crypto_state(%Workspace{} = workspace, kek_version) do
    if kek_version == workspace.current_kek_version,
      do: :ok,
      else: {:error, :kek_version_mismatch}
  end

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

  defp validate_scope_kind(_workspace_id, "workspace", nil), do: :ok

  defp validate_scope_kind(workspace_id, scope_kind, scope_id)
       when scope_kind in ["document", "folder"] and is_binary(scope_id) do
    case Repo.get(Document, scope_id) do
      %Document{workspace_id: ^workspace_id, doc_type: doc_type, archived_at: nil}
      when (scope_kind == "document" and doc_type == "document") or
             (scope_kind == "folder" and doc_type == "folder") ->
        :ok

      _ ->
        {:error, :invalid_scope}
    end
  end

  defp validate_scope_kind(workspace_id, "share", scope_id) when is_binary(scope_id) do
    case from(s in Share,
           join: d in Document,
           on: d.id == s.document_id,
           where: s.id == ^scope_id and d.workspace_id == ^workspace_id and is_nil(d.archived_at),
           limit: 1
         )
         |> Repo.one() do
      %Share{} -> :ok
      _ -> {:error, :invalid_scope}
    end
  end

  defp validate_scope_kind(_workspace_id, _scope_kind, _scope_id),
    do: {:error, :invalid_scope_kind}

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
      permission: attrs.permission,
      kek_version: attrs.kek_version,
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
    Repo.transaction(fun)
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
