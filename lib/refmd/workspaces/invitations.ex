defmodule RefMD.Workspaces.Invitations do
  @moduledoc false

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

  alias RefMD.Workspaces.Roles, as: WRoles

  @max_serialization_retries 3

  @spec create_invitation(map()) :: {:ok, WorkspaceInvitation.t()} | {:error, term()}
  def create_invitation(attrs) do
    create_invitation_with_retry(attrs, 0)
  end

  @max_accept_retries 3

  @spec accept_invitation(String.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def accept_invitation(token_hash, user_id, user_email) do
    accept_invitation_with_retry(token_hash, user_id, user_email, 0)
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

  # ── Create Invitation Private ───────────────────

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

  # ── Accept Invitation Private ───────────────────

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

  # ── Shared Private Helpers ──────────────────────

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
    case WRoles.get_default_role_with_permissions(workspace_id) do
      nil -> {:error, :no_default_role}
      role -> validate_member_invitation_role(role)
    end
  end

  defp resolve_invitation_role(%{role_id: role_id, workspace_id: workspace_id}) do
    case WRoles.get_role_with_permissions(workspace_id, role_id) do
      nil -> {:error, :invalid_role}
      role -> validate_member_invitation_role(role)
    end
  end

  defp validate_member_invitation_role(%{base_role: "guest"}), do: {:error, :invalid_role}
  defp validate_member_invitation_role(role), do: {:ok, role}

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

  defp check_rbac_permission(role, permission) do
    alias RefMDWeb.Plugs.RequireRBAC

    perms = RequireRBAC.effective_permissions(role)
    if MapSet.member?(perms, permission), do: :ok, else: {:error, :permission_denied}
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
