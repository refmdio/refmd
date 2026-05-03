defmodule RefMD.Workspaces.Guests do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Devices
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users

  alias RefMD.Workspaces.{
    GuestInvitation,
    Workspace,
    WorkspaceGuestGrant,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  @base_role_defaults %{
    "owner" => MapSet.new(~w(
        document:read document:write document:delete document:archive
        workspace:update workspace:admin workspace:delete
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "admin" => MapSet.new(~w(
        document:read document:write document:delete document:archive
        workspace:update workspace:admin
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "editor" => MapSet.new(~w(document:read document:write document:archive member:list)),
    "viewer" => MapSet.new(~w(document:read member:list)),
    "guest" => MapSet.new(~w(document:read document:write document:archive))
  }
  @transaction_retry_max 3

  @spec guest_user?(Ecto.UUID.t()) :: boolean()
  def guest_user?(user_id) do
    from(u in Users.User, where: u.id == ^user_id, select: u.account_type == "guest")
    |> Repo.one()
    |> Kernel.==(true)
  end

  @spec authorize_permission(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          atom() | String.t(),
          Document.t() | nil
        ) ::
          :ok | {:error, atom()}
  def authorize_permission(workspace_id, user_id, permission, document_or_conn \\ nil) do
    grants = active_grants(workspace_id, user_id)
    role = guest_workspace_role(workspace_id, user_id)

    cond do
      guest_context_invalid?(grants, role) -> {:error, :permission_denied}
      document_permission_denied?(role, permission) -> {:error, :permission_denied}
      true -> authorize_guest_permission(permission, grants, document_or_conn)
    end
  end

  defp guest_context_invalid?(grants, role), do: grants == [] or is_nil(role)

  defp document_permission_denied?(role, permission) do
    permission in ["document:read", "document:write", "document:archive"] and
      not permission_granted?(role, permission)
  end

  defp authorize_guest_permission(:membership, _grants, _document_or_conn), do: :ok

  defp authorize_guest_permission("member:list", _grants, _document_or_conn),
    do: {:error, :permission_denied}

  defp authorize_guest_permission("document:read", _grants, nil), do: :ok

  defp authorize_guest_permission("document:read", grants, document_or_conn) do
    if Enum.any?(grants, &grant_covers_document?(&1, document_or_conn)),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_guest_permission("document:write", grants, %Document{} = document) do
    authorize_write(grants, document)
  end

  defp authorize_guest_permission("document:archive", grants, %Document{} = document) do
    authorize_archive(grants, document)
  end

  defp authorize_guest_permission(_permission, _grants, _document_or_conn),
    do: {:error, :permission_denied}

  @spec authorize_document_create(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  def authorize_document_create(workspace_id, user_id, doc_type, parent_id)
      when doc_type in ["document", "folder"] do
    grants = active_grants(workspace_id, user_id)
    role = guest_workspace_role(workspace_id, user_id)

    cond do
      grants == [] or is_nil(role) ->
        {:error, :permission_denied}

      not permission_granted?(role, "document:write") ->
        {:error, :permission_denied}

      true ->
        authorize_create(grants, %{"doc_type" => doc_type, "parent_id" => parent_id})
    end
  end

  def authorize_document_create(_workspace_id, _user_id, _doc_type, _parent_id),
    do: {:error, :permission_denied}

  @spec authorize_document_reorder(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil,
          Ecto.UUID.t() | nil
        ) ::
          :ok | {:error, atom()}
  def authorize_document_reorder(workspace_id, user_id, document_id, parent_id) do
    grants = active_grants(workspace_id, user_id)
    role = guest_workspace_role(workspace_id, user_id)

    cond do
      grants == [] or is_nil(role) ->
        {:error, :permission_denied}

      not permission_granted?(role, "document:write") ->
        {:error, :permission_denied}

      true ->
        authorize_reorder(grants, %{"document_id" => document_id, "parent_id" => parent_id})
    end
  end

  @spec filter_documents(Ecto.UUID.t(), Ecto.UUID.t(), [Document.t()]) :: [Document.t()]
  def filter_documents(workspace_id, user_id, documents) do
    if guest_user?(user_id) do
      Enum.filter(documents, fn document ->
        authorize_permission(workspace_id, user_id, "document:read", document) == :ok
      end)
    else
      documents
    end
  end

  @spec create_guest_invitation(map()) :: {:ok, GuestInvitation.t()} | {:error, term()}
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
             validate_target_scope(
               attrs.workspace_id,
               attrs.target_scope,
               attrs.target_document_id
             ),
           {:ok, invitation} <- insert_guest_invitation(attrs) do
        invitation
      else
        nil -> Repo.rollback(:workspace_not_found)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @spec list_guest_invitations(Ecto.UUID.t()) :: [map()]
  def list_guest_invitations(workspace_id) do
    from(i in GuestInvitation,
      where: i.workspace_id == ^workspace_id and is_nil(i.revoked_at),
      select: %{
        invitation_id: i.id,
        workspace_id: i.workspace_id,
        token_prefix: i.token_prefix,
        target_scope: i.target_scope,
        target_document_id: i.target_document_id,
        permission: i.permission,
        invited_by: i.invited_by,
        kek_version: i.kek_version,
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

  @spec revoke_guest_invitation(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, GuestInvitation.t()} | {:error, term()}
  def revoke_guest_invitation(workspace_id, invitation_id, actor_user_id) do
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

        %{invitation | revoked_at: now}
      else
        nil -> Repo.rollback(:not_found)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @spec redeem_guest_invitation(String.t(), map(), map()) ::
          {:ok, map()} | {:error, term()}
  def redeem_guest_invitation(token_hash, device_attrs, session_attrs) do
    invitation =
      from(i in GuestInvitation, where: i.token_hash == ^token_hash)
      |> Repo.one()

    cond do
      invitation == nil ->
        {:error, :not_found}

      reused = find_existing_guest_device(invitation.workspace_id, device_attrs) ->
        issue_guest_session(reused, invitation, session_attrs)

      true ->
        create_guest_onboarding(invitation, device_attrs, session_attrs)
    end
  end

  @spec active_grants(Ecto.UUID.t(), Ecto.UUID.t()) :: [WorkspaceGuestGrant.t()]
  def active_grants(workspace_id, user_id) do
    from(g in WorkspaceGuestGrant,
      where:
        g.workspace_id == ^workspace_id and
          g.user_id == ^user_id and
          is_nil(g.revoked_at)
    )
    |> Repo.all()
  end

  @spec revoke_guest_grants(Ecto.UUID.t(), Ecto.UUID.t()) :: non_neg_integer()
  def revoke_guest_grants(workspace_id, user_id) do
    now = DateTime.utc_now()

    from(g in WorkspaceGuestGrant,
      where:
        g.workspace_id == ^workspace_id and
          g.user_id == ^user_id and
          is_nil(g.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: now])
    |> elem(0)
  end

  @spec guest_invites_enabled?(Ecto.UUID.t()) :: boolean()
  def guest_invites_enabled?(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, select: w.guest_invites_enabled)
    |> Repo.one()
    |> Kernel.==(true)
  end

  @spec revoke_all_active_guest_invitations([Ecto.UUID.t()]) :: non_neg_integer()
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

  @spec has_active_grants?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def has_active_grants?(workspace_id, user_id) do
    active_grants(workspace_id, user_id) != []
  end

  defp guest_workspace_role(workspace_id, user_id) do
    query =
      from(wm in WorkspaceMember,
        join: r in WorkspaceRole,
        on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
        left_join: p in WorkspaceRolePermission,
        on: p.role_id == r.id,
        where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
        select: {r, p}
      )

    case Repo.all(query) do
      [] ->
        nil

      rows ->
        {role, _permission} = hd(rows)

        permissions =
          rows
          |> Enum.map(fn {_role, permission} -> permission end)
          |> Enum.reject(&is_nil/1)

        %{role | permissions: permissions}
    end
  end

  defp create_guest_onboarding(invitation, device_attrs, session_attrs) do
    with_transaction_retry(fn ->
      fresh_invitation =
        from(i in GuestInvitation, where: i.id == ^invitation.id, lock: "FOR UPDATE")
        |> Repo.one()

      workspace =
        from(w in Workspace, where: w.id == ^fresh_invitation.workspace_id, lock: "FOR UPDATE")
        |> Repo.one()

      case validate_guest_onboarding_workspace(fresh_invitation, workspace) do
        {:ok, fresh_invitation, workspace} ->
          create_or_reuse_guest(fresh_invitation, workspace, device_attrs, session_attrs)

        nil ->
          Repo.rollback(:not_found)

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  defp validate_guest_onboarding_workspace(fresh_invitation, workspace) do
    with %GuestInvitation{} <- fresh_invitation,
         %Workspace{} <- workspace,
         :ok <- validate_workspace_settings(workspace) do
      {:ok, fresh_invitation, workspace}
    end
  end

  defp create_or_reuse_guest(fresh_invitation, workspace, device_attrs, session_attrs) do
    case find_existing_guest_device(workspace.id, device_attrs) do
      nil -> create_new_guest_redeem(fresh_invitation, workspace, device_attrs, session_attrs)
      reused -> complete_existing_guest_redeem(workspace, fresh_invitation, reused, session_attrs)
    end
  end

  defp create_new_guest_redeem(fresh_invitation, workspace, device_attrs, session_attrs) do
    with :ok <- validate_invitation_redeemable(fresh_invitation),
         :ok <- validate_workspace_crypto_state(workspace, fresh_invitation.kek_version),
         :ok <- validate_guest_member_limit_locked(workspace),
         {:ok, role} <- get_guest_workspace_role(workspace.id),
         {:ok, guest_user, guest_device} <- create_guest_principal_and_device(device_attrs),
         {:ok, _member} <- create_guest_membership(workspace.id, guest_user.id, role.id),
         {:ok, _grant} <- create_guest_grant(fresh_invitation, guest_user.id),
         :ok <- increment_redemption_count(fresh_invitation),
         {:ok, session_result} <-
           create_guest_session(guest_user.id, guest_device.id, session_attrs) do
      build_redeem_result(
        fresh_invitation,
        workspace,
        guest_user.id,
        guest_device.id,
        session_result
      )
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp issue_guest_session(reused, invitation, session_attrs) do
    with_transaction_retry(fn ->
      fresh_invitation =
        from(i in GuestInvitation, where: i.id == ^invitation.id, lock: "FOR UPDATE")
        |> Repo.one()

      workspace =
        from(w in Workspace, where: w.id == ^invitation.workspace_id, lock: "FOR UPDATE")
        |> Repo.one()

      with %GuestInvitation{} <- fresh_invitation,
           %Workspace{} <- workspace,
           :ok <- validate_workspace_settings(workspace) do
        complete_existing_guest_redeem(workspace, fresh_invitation, reused, session_attrs)
      else
        nil -> Repo.rollback(:not_found)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp complete_existing_guest_redeem(
         workspace,
         invitation,
         reused,
         session_attrs,
         grant \\ nil
       ) do
    grant = grant || get_active_guest_grant(workspace.id, reused.user_id)

    with %WorkspaceGuestGrant{} <- grant,
         :ok <-
           validate_existing_guest_device_access(workspace.id, reused.user_id, reused.device_id),
         :ok <- validate_existing_guest_redeem(workspace, invitation, grant, reused.user_id),
         {:ok, session_result} <-
           create_guest_session(reused.user_id, reused.device_id, session_attrs) do
      build_redeem_result(
        invitation,
        workspace,
        reused.user_id,
        reused.device_id,
        session_result
      )
    else
      nil -> Repo.rollback(:not_found)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp create_guest_session(user_id, device_id, session_attrs) do
    case Auth.create_session(user_id, %{
           device_id: device_id,
           remember_me: false,
           ip_address: Map.get(session_attrs, :ip_address),
           user_agent: Map.get(session_attrs, :user_agent)
         }) do
      {:ok, session, token} ->
        {:ok, %{session: session, token: token}}

      {:error, _changeset} ->
        {:error, :session_creation_failed}
    end
  end

  defp build_redeem_result(
         invitation,
         workspace,
         user_id,
         device_id,
         session_result,
         extra \\ %{}
       ) do
    Map.merge(
      %{
        workspace_id: workspace.id,
        workspace_name: workspace.name,
        invitation_id: invitation.id,
        target_scope: invitation.target_scope,
        target_document_id: invitation.target_document_id,
        permission: invitation.permission,
        guest_user_id: user_id,
        guest_device_id: device_id,
        encrypted_kek: invitation.encrypted_kek,
        kek_nonce: invitation.kek_nonce,
        kek_version: invitation.kek_version,
        session: session_result.session,
        session_token: session_result.token
      },
      extra
    )
  end

  defp find_existing_guest_device(workspace_id, device_attrs) do
    from(g in WorkspaceGuestGrant,
      join: d in RefMD.Devices.Device,
      on: d.user_id == g.user_id,
      join: mk in RefMD.Encryption.UserEncryptedMasterKey,
      on: mk.user_id == g.user_id,
      join: ik in RefMD.Encryption.UserEncryptedIdentityKey,
      on: ik.user_id == g.user_id,
      where: g.workspace_id == ^workspace_id and is_nil(g.revoked_at) and is_nil(d.revoked_at),
      where: d.signing_public_key == ^device_attrs.device_signing_pub_key,
      where: d.ecdh_public_key == ^device_attrs.device_encryption_pub_key,
      where: d.client_nonce == ^device_attrs.client_nonce,
      where: d.identity_signature == ^device_attrs.identity_signature,
      where: mk.recovery_encrypted_umk == ^device_attrs.recovery_encrypted_umk,
      where: mk.recovery_nonce == ^device_attrs.recovery_nonce,
      where: ik.encrypted_ecdh_private == ^device_attrs.encrypted_identity_encryption_private,
      where:
        ik.encrypted_ecdh_private_nonce ==
          ^device_attrs.encrypted_identity_encryption_private_nonce,
      where: ik.encrypted_signing_private == ^device_attrs.encrypted_identity_signing_private,
      where:
        ik.encrypted_signing_private_nonce ==
          ^device_attrs.encrypted_identity_signing_private_nonce,
      select: %{user_id: g.user_id, device_id: d.id},
      limit: 1
    )
    |> Repo.one()
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
    alias RefMDWeb.Plugs.RequireRBAC

    if role |> RequireRBAC.effective_permissions() |> MapSet.member?("guest:invite"),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp validate_guest_role_escalation(actor_role, target_role, invitation_permission) do
    alias RefMDWeb.Plugs.RequireRBAC

    actor_permissions = RequireRBAC.effective_permissions(actor_role)

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
    alias RefMDWeb.Plugs.RequireRBAC

    target_role
    |> RequireRBAC.effective_permissions()
    |> MapSet.intersection(MapSet.new(["document:read", "document:write", "document:archive"]))
  end

  defp validate_guest_reentry_crypto_state(%Workspace{needs_kek_rotation: true}, _invitation),
    do: {:error, :kek_rotation_in_progress}

  defp validate_guest_reentry_crypto_state(workspace, invitation) do
    if invitation.kek_version >= workspace.min_kek_version,
      do: :ok,
      else: {:error, :invitation_kek_outdated}
  end

  defp permission_granted?(%{base_role: "owner"}, _permission), do: true

  defp permission_granted?(role, permission) do
    defaults = Map.get(@base_role_defaults, role.base_role, MapSet.new())

    case Enum.find(role.permissions || [], &(&1.permission == permission)) do
      nil -> MapSet.member?(defaults, permission)
      override -> override.granted
    end
  end

  defp validate_target_scope(_workspace_id, "workspace", nil), do: :ok

  defp validate_target_scope(workspace_id, target_scope, target_document_id)
       when target_scope in ["document", "folder"] and is_binary(target_document_id) do
    case Repo.get(Document, target_document_id) do
      %Document{workspace_id: ^workspace_id, doc_type: doc_type, archived_at: nil}
      when (target_scope == "document" and doc_type == "document") or
             (target_scope == "folder" and doc_type == "folder") ->
        :ok

      _ ->
        {:error, :invalid_target_document}
    end
  end

  defp validate_target_scope(_workspace_id, _target_scope, _target_document_id),
    do: {:error, :invalid_target_document}

  defp insert_guest_invitation(attrs) do
    now = DateTime.utc_now()

    %GuestInvitation{created_at: now}
    |> GuestInvitation.changeset(%{
      id: attrs.invitation_id,
      workspace_id: attrs.workspace_id,
      token_hash: attrs.token_hash,
      token_prefix: attrs.token_prefix,
      target_scope: attrs.target_scope,
      target_document_id: attrs.target_document_id,
      permission: attrs.permission,
      encrypted_kek: attrs.encrypted_kek,
      kek_nonce: attrs.kek_nonce,
      kek_version: attrs.kek_version,
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

      foreign_constraint_error?(changeset, :target_document_id) ->
        {:error, :invalid_target_document}

      true ->
        {:error, changeset}
    end
  end

  defp validate_invitation_redeemable(invitation) do
    now = DateTime.utc_now()

    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, now) != :gt ->
        {:error, :invitation_expired}

      invitation.redemption_count >= invitation.max_redemptions ->
        {:error, :invitation_redemptions_exhausted}

      true ->
        :ok
    end
  end

  defp validate_existing_guest_redeem(workspace, invitation, grant, user_id) do
    if grant.invite_id == invitation.id do
      with :ok <- validate_guest_reentry_crypto_state(workspace, invitation),
           {:ok, role} <- get_guest_workspace_role(workspace.id) do
        sync_guest_membership_role(workspace.id, user_id, role)
      end
    else
      with :ok <- validate_invitation_redeemable(invitation),
           :ok <- validate_workspace_crypto_state(workspace, invitation.kek_version),
           {:ok, role} <- get_guest_workspace_role(workspace.id),
           :ok <- sync_guest_membership_role(workspace.id, user_id, role),
           {:ok, _grant} <- replace_guest_grant(grant, invitation) do
        increment_redemption_count(invitation)
      end
    end
  end

  defp validate_guest_member_limit_locked(%Workspace{} = workspace) do
    if is_nil(workspace.guest_member_limit) do
      :ok
    else
      count =
        from(g in WorkspaceGuestGrant,
          join: u in Users.User,
          on: u.id == g.user_id,
          where:
            g.workspace_id == ^workspace.id and
              is_nil(g.revoked_at) and
              u.account_type == "guest",
          select: count(g.user_id, :distinct)
        )
        |> Repo.one()

      if count < workspace.guest_member_limit,
        do: :ok,
        else: {:error, :guest_member_limit_reached}
    end
  end

  defp validate_existing_guest_device_access(workspace_id, user_id, device_id) do
    exists? =
      from(g in WorkspaceGuestGrant,
        join: d in RefMD.Devices.Device,
        on: d.user_id == g.user_id,
        join: wm in WorkspaceMember,
        on: wm.workspace_id == g.workspace_id and wm.user_id == g.user_id,
        where:
          g.workspace_id == ^workspace_id and
            g.user_id == ^user_id and
            is_nil(g.revoked_at) and
            d.id == ^device_id and
            is_nil(d.revoked_at),
        select: 1,
        limit: 1
      )
      |> Repo.one()

    if exists?, do: :ok, else: {:error, :not_found}
  end

  defp get_active_guest_grant(workspace_id, user_id) do
    from(g in WorkspaceGuestGrant,
      where:
        g.workspace_id == ^workspace_id and
          g.user_id == ^user_id and
          is_nil(g.revoked_at),
      limit: 1
    )
    |> Repo.one()
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

  defp create_guest_principal_and_device(device_attrs) do
    user_id = Map.get(device_attrs, :guest_user_id) || Ecto.UUID.generate()

    if Users.get_user(user_id) do
      {:error, :guest_user_id_conflict}
    else
      do_create_guest_principal_and_device(user_id, device_attrs)
    end
  end

  defp do_create_guest_principal_and_device(user_id, device_attrs) do
    Repo.transaction(fn ->
      with {:ok, user} <- create_guest_user(user_id),
           {:ok, _settings} <- Users.create_user_settings(user.id),
           {:ok, _identity_keys} <- create_guest_identity_public_key(user.id, device_attrs),
           {:ok, _master_key} <- create_guest_master_key(user.id, device_attrs),
           {:ok, _identity_key} <- create_guest_identity_private_key(user.id, device_attrs),
           {:ok, device} <- bootstrap_guest_device(user.id, device_attrs) do
        {user, device}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, {user, device}} -> {:ok, user, device}
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_guest_user(user_id) do
    Users.create_user_with_struct(%Users.User{id: user_id}, %{
      email: "guest-" <> user_id <> "@guest.refmd.local",
      name: "Guest " <> String.slice(user_id, 0, 8),
      account_type: "guest"
    })
  end

  defp create_guest_identity_public_key(user_id, device_attrs) do
    Encryption.create_user_identity_public_key(%{
      user_id: user_id,
      ecdh_public_key: device_attrs.identity_encryption_pub_key,
      signing_public_key: device_attrs.identity_signing_pub_key
    })
  end

  defp create_guest_master_key(user_id, device_attrs) do
    Encryption.create_user_encrypted_master_key(%{
      user_id: user_id,
      auth_type: "oauth",
      recovery_encrypted_umk: device_attrs.recovery_encrypted_umk,
      recovery_nonce: device_attrs.recovery_nonce
    })
  end

  defp create_guest_identity_private_key(user_id, device_attrs) do
    Encryption.create_user_encrypted_identity_key(%{
      user_id: user_id,
      encrypted_ecdh_private: device_attrs.encrypted_identity_encryption_private,
      encrypted_ecdh_private_nonce: device_attrs.encrypted_identity_encryption_private_nonce,
      encrypted_signing_private: device_attrs.encrypted_identity_signing_private,
      encrypted_signing_private_nonce: device_attrs.encrypted_identity_signing_private_nonce
    })
  end

  defp bootstrap_guest_device(user_id, device_attrs) do
    Devices.bootstrap_first_device(
      %{
        user_id: user_id,
        name: Map.get(device_attrs, :device_name, "Guest Browser"),
        device_type: Map.get(device_attrs, :device_type, "browser"),
        ecdh_public_key: device_attrs.device_encryption_pub_key,
        signing_public_key: device_attrs.device_signing_pub_key,
        client_nonce: device_attrs.client_nonce
      },
      device_attrs.identity_signature
    )
  end

  defp create_guest_membership(workspace_id, user_id, role_id) do
    %WorkspaceMember{joined_at: DateTime.utc_now()}
    |> WorkspaceMember.changeset(%{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role_id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  defp create_guest_grant(invitation, user_id) do
    %WorkspaceGuestGrant{created_at: DateTime.utc_now()}
    |> WorkspaceGuestGrant.changeset(%{
      workspace_id: invitation.workspace_id,
      user_id: user_id,
      target_scope: invitation.target_scope,
      target_document_id: invitation.target_document_id,
      permission: invitation.permission,
      invite_id: invitation.id
    })
    |> Repo.insert()
  end

  defp replace_guest_grant(grant, invitation) do
    attrs = %{
      target_scope: invitation.target_scope,
      target_document_id: invitation.target_document_id,
      permission: invitation.permission,
      invite_id: invitation.id,
      revoked_at: nil,
      created_at: DateTime.utc_now()
    }

    case grant |> Ecto.Changeset.change(attrs) |> Repo.update() do
      {:ok, updated_grant} -> {:ok, updated_grant}
      {:error, reason} -> {:error, reason}
    end
  end

  defp sync_guest_membership_role(workspace_id, user_id, target_role) do
    current =
      from(m in WorkspaceMember,
        join: r in WorkspaceRole,
        on: r.id == m.role_id,
        where: m.workspace_id == ^workspace_id and m.user_id == ^user_id,
        select: %{role_id: m.role_id, base_role: r.base_role},
        limit: 1
      )
      |> Repo.one()

    cond do
      is_nil(current) ->
        {:error, :not_found}

      current.role_id != target_role.id ->
        from(m in WorkspaceMember,
          where: m.workspace_id == ^workspace_id and m.user_id == ^user_id
        )
        |> Repo.update_all(set: [role_id: target_role.id])

        :ok

      true ->
        :ok
    end
  end

  defp increment_redemption_count(invitation) do
    {count, _} =
      from(i in GuestInvitation,
        where: i.id == ^invitation.id and i.redemption_count < i.max_redemptions
      )
      |> Repo.update_all(inc: [redemption_count: 1])

    if count == 1, do: :ok, else: {:error, :invitation_redemptions_exhausted}
  end

  defp active_document?(%Document{workspace_id: workspace_id}, workspace_id), do: true
  defp active_document?(_, _), do: false

  defp authorize_write(grants, %Document{} = document) do
    if Enum.any?(grants, &(&1.permission == "edit" and grant_covers_document?(&1, document))),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_archive(grants, %Document{} = document) do
    if Enum.any?(grants, &(&1.permission == "edit" and grant_covers_document?(&1, document))),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_create(grants, %{"doc_type" => doc_type} = params)
       when doc_type in ["document", "folder"] do
    parent =
      case Map.get(params, "parent_id") do
        nil -> nil
        parent_id -> Repo.get(Document, parent_id)
      end

    if Enum.any?(grants, &grant_allows_create?(&1, parent)),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_create(_grants, _params), do: {:error, :permission_denied}

  defp grant_allows_create?(
         %WorkspaceGuestGrant{permission: "edit", target_scope: "workspace"},
         _parent
       ),
       do: true

  defp grant_allows_create?(
         %WorkspaceGuestGrant{permission: "edit", target_scope: "folder"} = grant,
         %Document{} = parent
       ) do
    grant_covers_document?(grant, parent)
  end

  defp grant_allows_create?(_grant, _parent), do: false

  defp authorize_reorder(grants, %{"document_id" => document_id} = params) do
    document = Repo.get(Document, document_id)

    parent =
      case Map.get(params, "parent_id") do
        nil -> nil
        parent_id -> Repo.get(Document, parent_id)
      end

    if document &&
         Enum.any?(grants, fn grant ->
           grant.permission == "edit" and grant_allows_reorder_document?(grant, document, parent)
         end) do
      :ok
    else
      {:error, :permission_denied}
    end
  end

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{target_scope: "workspace"},
         _document,
         _parent
       ),
       do: true

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{target_scope: "folder"},
         %Document{},
         nil
       ),
       do: false

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{target_scope: "folder"} = grant,
         %Document{} = document,
         %Document{} = parent
       ) do
    grant_covers_document?(grant, document) and grant_covers_document?(grant, parent)
  end

  defp grant_allows_reorder_document?(_grant, _document, _parent), do: false

  defp grant_covers_document?(%WorkspaceGuestGrant{target_scope: "workspace"} = grant, document) do
    active_document?(document, grant.workspace_id)
  end

  defp grant_covers_document?(
         %WorkspaceGuestGrant{target_scope: "document", target_document_id: target_id},
         %Document{id: document_id}
       ) do
    target_id == document_id
  end

  defp grant_covers_document?(
         %WorkspaceGuestGrant{target_scope: "folder", target_document_id: folder_id},
         %Document{id: document_id}
       ) do
    document_id == folder_id or document_descends_from?(document_id, folder_id)
  end

  defp document_descends_from?(document_id, folder_id) do
    case Repo.get(Document, document_id) do
      nil ->
        false

      %Document{parent_id: nil} ->
        false

      %Document{parent_id: ^folder_id} ->
        true

      %Document{parent_id: parent_id} ->
        document_descends_from?(parent_id, folder_id)
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
