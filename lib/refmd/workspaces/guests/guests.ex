defmodule RefMD.Workspaces.Guests do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Devices
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Workspaces.Invitations.KeyDirectory

  alias RefMD.Workspaces.{
    GuestInvitation,
    Workspace,
    WorkspaceGuestGrant
  }

  @transaction_retry_max 3

  @spec guest_user?(Ecto.UUID.t()) :: boolean()
  defdelegate guest_user?(user_id), to: RefMD.Workspaces.Guests.Authorization

  @spec guest_role_for_active_grants(Ecto.UUID.t(), Ecto.UUID.t()) ::
          RefMD.Workspaces.WorkspaceRole.t() | nil
  defdelegate guest_role_for_active_grants(workspace_id, user_id),
    to: RefMD.Workspaces.Guests.Authorization,
    as: :role_for_active_grants

  @spec authorize_permission(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          atom() | String.t(),
          Document.t() | nil
        ) ::
          :ok | {:error, atom()}
  defdelegate authorize_permission(workspace_id, user_id, permission, document_or_conn \\ nil),
    to: RefMD.Workspaces.Guests.Authorization

  @spec authorize_document_create(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  defdelegate authorize_document_create(workspace_id, user_id, doc_type, parent_id),
    to: RefMD.Workspaces.Guests.Authorization

  @spec authorize_document_reorder(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil,
          Ecto.UUID.t() | nil
        ) ::
          :ok | {:error, atom()}
  defdelegate authorize_document_reorder(workspace_id, user_id, document_id, parent_id),
    to: RefMD.Workspaces.Guests.Authorization

  @spec filter_documents(Ecto.UUID.t(), Ecto.UUID.t(), [Document.t()]) :: [Document.t()]
  defdelegate filter_documents(workspace_id, user_id, documents),
    to: RefMD.Workspaces.Guests.Authorization

  @spec create_guest_invitation(map()) :: {:ok, GuestInvitation.t()} | {:error, term()}
  defdelegate create_guest_invitation(attrs), to: RefMD.Workspaces.Guests.Invitations

  @spec list_guest_invitations(Ecto.UUID.t()) :: [map()]
  defdelegate list_guest_invitations(workspace_id), to: RefMD.Workspaces.Guests.Invitations

  @spec revoke_guest_invitation(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, GuestInvitation.t()} | {:error, term()}
  defdelegate revoke_guest_invitation(workspace_id, invitation_id, actor_user_id),
    to: RefMD.Workspaces.Guests.Invitations

  @spec revoke_guest_invitation(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), map() | nil) ::
          {:ok, GuestInvitation.t()} | {:error, term()}
  defdelegate revoke_guest_invitation(workspace_id, invitation_id, actor_user_id, key_directory),
    to: RefMD.Workspaces.Guests.Invitations

  @spec redeem_guest_invitation(String.t(), map(), map()) ::
          {:ok, map()} | {:error, term()}
  def redeem_guest_invitation(token_hash, device_attrs, session_attrs) do
    redeem_guest_invitation(token_hash, device_attrs, session_attrs, nil)
  end

  @spec redeem_guest_invitation(String.t(), map(), map(), map() | nil) ::
          {:ok, map()} | {:error, term()}
  def redeem_guest_invitation(token_hash, device_attrs, session_attrs, key_directory) do
    invitation =
      from(i in GuestInvitation, where: i.token_hash == ^token_hash)
      |> Repo.one()

    cond do
      invitation == nil ->
        {:error, :not_found}

      reused = find_existing_guest_device(invitation.workspace_id, device_attrs) ->
        issue_guest_session(reused, invitation, session_attrs, key_directory)

      true ->
        create_guest_onboarding(invitation, device_attrs, session_attrs, key_directory)
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
  defdelegate guest_invites_enabled?(workspace_id), to: RefMD.Workspaces.Guests.Invitations

  @spec revoke_all_active_guest_invitations([Ecto.UUID.t()]) :: non_neg_integer()
  defdelegate revoke_all_active_guest_invitations(workspace_ids),
    to: RefMD.Workspaces.Guests.Invitations

  @spec has_active_grants?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def has_active_grants?(workspace_id, user_id) do
    active_grants(workspace_id, user_id) != []
  end

  @spec active_guest_device_workspace_id(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Ecto.UUID.t()} | {:error, :not_found}
  def active_guest_device_workspace_id(user_id, device_id) do
    from(g in WorkspaceGuestGrant,
      join: d in RefMD.Devices.Device,
      on: d.user_id == g.user_id,
      where:
        g.user_id == ^user_id and
          d.id == ^device_id and
          is_nil(g.revoked_at) and
          is_nil(d.revoked_at),
      order_by: [desc: g.created_at, desc: g.workspace_id],
      select: g.workspace_id,
      limit: 1
    )
    |> Repo.one()
    |> case do
      workspace_id when is_binary(workspace_id) -> {:ok, workspace_id}
      _ -> {:error, :not_found}
    end
  end

  defp create_guest_onboarding(invitation, device_attrs, session_attrs, key_directory) do
    with_transaction_retry(fn ->
      fresh_invitation =
        from(i in GuestInvitation, where: i.id == ^invitation.id, lock: "FOR UPDATE")
        |> Repo.one()

      workspace =
        from(w in Workspace, where: w.id == ^fresh_invitation.workspace_id, lock: "FOR UPDATE")
        |> Repo.one()

      case validate_guest_onboarding_workspace(fresh_invitation, workspace) do
        {:ok, fresh_invitation, workspace} ->
          create_or_reuse_guest(
            fresh_invitation,
            workspace,
            device_attrs,
            session_attrs,
            key_directory
          )

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

  defp create_or_reuse_guest(
         fresh_invitation,
         workspace,
         device_attrs,
         session_attrs,
         key_directory
       ) do
    case find_existing_guest_device(workspace.id, device_attrs) do
      nil ->
        create_new_guest_redeem(
          fresh_invitation,
          workspace,
          device_attrs,
          session_attrs,
          key_directory
        )

      reused ->
        complete_existing_guest_redeem(
          workspace,
          fresh_invitation,
          reused,
          session_attrs,
          key_directory
        )
    end
  end

  defp create_new_guest_redeem(
         fresh_invitation,
         workspace,
         device_attrs,
         session_attrs,
         key_directory
       ) do
    with :ok <- validate_new_guest_redemption_available(fresh_invitation),
         :ok <- validate_workspace_crypto_state(workspace, fresh_invitation.kek_version),
         :ok <- validate_guest_member_limit_locked(workspace),
         {:ok, guest_user, guest_device} <-
           create_guest_principal_and_device(device_attrs, key_directory),
         guest_grant_id = guest_grant_id!(key_directory),
         :ok <-
           append_guest_redeem_key_directory!(
             fresh_invitation,
             guest_grant_id,
             guest_user.id,
             guest_device.id,
             guest_device.encryption_key_id,
             guest_device.signing_key_id,
             key_directory
           ),
         {:ok, session_result} <-
           create_guest_session(guest_user.id, guest_device.id, session_attrs),
         {:ok, _grant} <- upsert_guest_grant(fresh_invitation, guest_user.id, guest_grant_id),
         :ok <- increment_guest_redemption_count(fresh_invitation) do
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

  defp issue_guest_session(reused, invitation, session_attrs, key_directory) do
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
        complete_existing_guest_redeem(
          workspace,
          fresh_invitation,
          reused,
          session_attrs,
          key_directory
        )
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
         key_directory,
         grant \\ nil
       ) do
    grant = grant || get_active_guest_grant(workspace.id, reused.user_id)

    with %WorkspaceGuestGrant{} <- grant,
         :ok <-
           validate_existing_guest_device_access(workspace.id, reused.user_id, reused.device_id) do
      if grant.invite_id == invitation.id do
        reenter_existing_guest(workspace, invitation, reused, session_attrs)
      else
        request_existing_guest_readmission(
          workspace,
          invitation,
          reused,
          session_attrs,
          key_directory
        )
      end
    else
      nil -> Repo.rollback(:not_found)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp reenter_existing_guest(workspace, invitation, reused, session_attrs) do
    with :ok <- validate_guest_reentry_invitation_active(invitation),
         :ok <- validate_guest_reentry_crypto_state(workspace, invitation),
         {:ok, session_result} <-
           create_guest_session(reused.user_id, reused.device_id, session_attrs) do
      build_redeem_result(
        invitation,
        workspace,
        reused.user_id,
        reused.device_id,
        session_result
      )
    end
  end

  defp request_existing_guest_readmission(
         workspace,
         invitation,
         reused,
         session_attrs,
         key_directory
       ) do
    with :ok <- validate_new_guest_redemption_available(invitation),
         :ok <- validate_workspace_crypto_state(workspace, invitation.kek_version),
         {:ok, guest_user} <- fetch_guest_user(reused.user_id),
         {:ok, guest_device} <- fetch_guest_device(reused.device_id),
         guest_grant_id = guest_grant_id!(key_directory),
         :ok <-
           append_guest_redeem_key_directory!(
             invitation,
             guest_grant_id,
             guest_user.id,
             reused.device_id,
             guest_device.encryption_key_id,
             guest_device.signing_key_id,
             key_directory
           ),
         {:ok, session_result} <-
           create_guest_session(reused.user_id, reused.device_id, session_attrs),
         {:ok, _grant} <- upsert_guest_grant(invitation, guest_user.id, guest_grant_id),
         :ok <- increment_guest_redemption_count(invitation) do
      build_redeem_result(
        invitation,
        workspace,
        reused.user_id,
        reused.device_id,
        session_result
      )
    end
  end

  defp append_guest_redeem_key_directory!(
         invitation,
         guest_grant_id,
         guest_user_id,
         guest_device_id,
         guest_encryption_key_id,
         guest_signing_key_id,
         key_directory
       ) do
    KeyDirectory.append_if_present(key_directory, %{
      kind: :guest_invitation_redeemed,
      workspace_id: invitation.workspace_id,
      redeem_authority_signing_key_id: redeem_authority_signing_key_id!(key_directory),
      invitation: invitation,
      guest_grant_id: guest_grant_id,
      guest_user_id: guest_user_id,
      guest_device_id: guest_device_id,
      guest_encryption_key_id: guest_encryption_key_id,
      guest_signing_key_id: guest_signing_key_id
    })
  end

  defp redeem_authority_signing_key_id!(%{events: events}) when is_list(events) do
    events
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => "guest_invitation_redeemed", "actor" => actor}}
      when is_map(actor) ->
        actor["signing_key_id"]

      _ ->
        nil
    end)
    |> case do
      key_id when is_binary(key_id) -> key_id
      _ -> raise ArgumentError, "redeem_authority_missing"
    end
  end

  defp guest_grant_id!(%{events: events}) when is_list(events) do
    grant_id =
      events
      |> Enum.find_value(fn
        %{"payload" => %{"event_type" => "guest_invitation_redeemed", "body" => body}}
        when is_map(body) ->
          body["guest_grant_id"]

        _ ->
          nil
      end)

    case Ecto.UUID.cast(grant_id) do
      {:ok, valid_grant_id} -> valid_grant_id
      :error -> raise ArgumentError, "guest_grant_id_invalid"
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
        scope_kind: invitation.scope_kind,
        scope_id: invitation.scope_id,
        permission: invitation.permission,
        guest_user_id: user_id,
        guest_device_id: device_id,
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
      where: g.workspace_id == ^workspace_id and is_nil(g.revoked_at) and is_nil(d.revoked_at),
      where: d.id == ^device_attrs.device_id,
      where:
        d.hybrid_encryption_public_key_material ==
          ^device_attrs.device_hybrid_encryption_public_key_material,
      where:
        d.hybrid_signing_public_key_material ==
          ^device_attrs.device_hybrid_signing_public_key_material,
      where: d.client_nonce == ^device_attrs.client_nonce,
      where: d.approval_signature == ^device_attrs.approval_signature,
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

  defp validate_guest_reentry_crypto_state(%Workspace{needs_kek_rotation: true}, _invitation),
    do: {:error, :kek_rotation_in_progress}

  defp validate_guest_reentry_crypto_state(workspace, invitation) do
    if invitation.kek_version >= workspace.min_kek_version,
      do: :ok,
      else: {:error, :invitation_kek_outdated}
  end

  defp validate_guest_reentry_invitation_active(invitation) do
    now = DateTime.utc_now()

    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, now) != :gt ->
        {:error, :invitation_expired}

      true ->
        :ok
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

  defp validate_new_guest_redemption_available(invitation) do
    with :ok <- validate_invitation_redeemable(invitation) do
      if invitation.redemption_count < invitation.max_redemptions,
        do: :ok,
        else: {:error, :invitation_redemptions_exhausted}
    end
  end

  defp upsert_guest_grant(invitation, user_id, guest_grant_id) do
    %WorkspaceGuestGrant{created_at: DateTime.utc_now()}
    |> WorkspaceGuestGrant.changeset(%{
      workspace_id: invitation.workspace_id,
      user_id: user_id,
      id: guest_grant_id,
      scope_kind: invitation.scope_kind,
      scope_id: invitation.scope_id,
      permission: invitation.permission,
      invite_id: invitation.id
    })
    |> Repo.insert(
      on_conflict: [
        set: [
          id: guest_grant_id,
          scope_kind: invitation.scope_kind,
          scope_id: invitation.scope_id,
          permission: invitation.permission,
          invite_id: invitation.id,
          revoked_at: nil,
          created_at: DateTime.utc_now()
        ]
      ],
      conflict_target: [:workspace_id, :user_id]
    )
    |> case do
      {:ok, grant} -> {:ok, grant}
      {:error, _changeset} -> {:error, :guest_grant_insert_failed}
    end
  end

  defp increment_guest_redemption_count(invitation) do
    case from(i in GuestInvitation,
           where: i.id == ^invitation.id and i.redemption_count < i.max_redemptions
         )
         |> Repo.update_all(inc: [redemption_count: 1]) do
      {1, _} -> :ok
      _ -> {:error, :invitation_redemptions_exhausted}
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

  defp fetch_guest_user(user_id) do
    case Users.get_user(user_id) do
      %RefMD.Users.User{account_type: "guest"} = user -> {:ok, user}
      _ -> {:error, :not_found}
    end
  end

  defp fetch_guest_device(device_id) do
    case Devices.get_device(device_id) do
      %RefMD.Devices.Device{revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :not_found}
    end
  end

  defp create_guest_principal_and_device(device_attrs, key_directory) do
    user_id = Map.get(device_attrs, :guest_user_id) || Ecto.UUID.generate()

    if Users.get_user(user_id) do
      {:error, :guest_user_id_conflict}
    else
      do_create_guest_principal_and_device(user_id, device_attrs, key_directory)
    end
  end

  defp do_create_guest_principal_and_device(user_id, device_attrs, key_directory) do
    Repo.transaction(fn ->
      with {:ok, user} <- create_guest_user(user_id),
           {:ok, _settings} <- Users.create_user_settings(user.id),
           {:ok, _identity_keys} <- create_guest_identity_public_key(user.id, device_attrs),
           {:ok, device} <- bootstrap_guest_device(user.id, device_attrs, key_directory) do
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
      hybrid_encryption_public_key_material:
        device_attrs.identity_hybrid_encryption_public_key_material,
      hybrid_signing_public_key_material:
        device_attrs.identity_hybrid_signing_public_key_material,
      pending_registration_challenge_hash: device_attrs.pending_registration_challenge_hash
    })
  end

  defp bootstrap_guest_device(user_id, device_attrs, %{checkpoint: checkpoint}) do
    Devices.bootstrap_guest_device(
      %{
        user_id: user_id,
        id: device_attrs.device_id,
        name: Map.get(device_attrs, :device_name, "Guest Browser"),
        device_type: Map.get(device_attrs, :device_type, "browser"),
        hybrid_encryption_public_key_material:
          device_attrs.device_hybrid_encryption_public_key_material,
        hybrid_signing_public_key_material:
          device_attrs.device_hybrid_signing_public_key_material,
        client_nonce: device_attrs.client_nonce,
        pending_registration_challenge_hash: device_attrs.pending_registration_challenge_hash
      },
      device_attrs.approval_signature,
      checkpoint
    )
  end

  defp bootstrap_guest_device(_user_id, _device_attrs, _key_directory),
    do: {:error, :missing_key_directory}

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
end
