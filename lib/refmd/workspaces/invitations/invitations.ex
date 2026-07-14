defmodule RefMD.Workspaces.Invitations do
  @moduledoc false

  import Ecto.Query
  alias RefMD.Crypto.Encoding
  alias RefMD.Devices
  alias RefMD.Encryption
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Workspaces.Invitations.KeyDirectory

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceInvitation,
    WorkspaceMember,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  alias RefMD.Workspaces.Roles, as: WRoles

  @max_serialization_retries 3

  def lookup_ancestry(
        workspace_id,
        created_event_type,
        invitation_body_key,
        invitation_id,
        current_checkpoint
      ) do
    Encryption.workspace_key_directory_ancestry_for_body_field(
      workspace_id,
      created_event_type,
      invitation_body_key,
      invitation_id,
      current_checkpoint
    )
  end

  def validate_encrypted_bootstrap_package(package, workspace_id, key_version)
      when is_map(package) and is_integer(key_version) do
    with encrypted_payload when is_map(encrypted_payload) <- package["encrypted_payload"],
         recipient_wrap when is_map(recipient_wrap) <- package["package_key_recipient_wrap"],
         maintenance_wrap when is_map(maintenance_wrap) <-
           package["package_key_maintenance_wrap"],
         aad when is_map(aad) <- package["aad"],
         key_context when is_map(key_context) <- aad["key_version_context"],
         true <-
           exact_keys?(package, [
             "aad",
             "encrypted_payload",
             "key_version",
             "package_key_maintenance_wrap",
             "package_key_recipient_wrap",
             "protocol",
             "suite_id",
             "version",
             "workspace_id"
           ]),
         true <- exact_keys?(encrypted_payload, ["ciphertext", "nonce"]),
         :ok <-
           validate_recipient_wrap(recipient_wrap, aad, workspace_id, key_version),
         true <- exact_keys?(maintenance_wrap, ["ciphertext", "key_version", "nonce"]),
         true <-
           exact_keys?(aad, [
             "invitation_id",
             "invited_email",
             "delivery_mode",
             "recipient_user_id",
             "recipient_device_ids",
             "key_version_context",
             "protocol",
             "role_id",
             "suite_id",
             "token_hash",
             "version",
             "workspace_id"
           ]),
         true <- exact_keys?(key_context, ["workspace_kek_version"]),
         true <- package["protocol"] == "refmd.workspace-invitation-bootstrap",
         true <- package["version"] == 1,
         true <- package["suite_id"] == "refmd-v2-invitation-bootstrap-xchacha20poly1305",
         true <- package["workspace_id"] == workspace_id,
         true <- package["key_version"] == key_version,
         true <- aad["protocol"] == package["protocol"],
         true <- aad["version"] == 1,
         true <- aad["suite_id"] == package["suite_id"],
         true <- aad["workspace_id"] == workspace_id,
         true <- key_context["workspace_kek_version"] == key_version,
         true <- is_binary(aad["invitation_id"]),
         true <- is_binary(aad["role_id"]),
         true <- is_binary(aad["invited_email"]),
         true <- is_binary(aad["token_hash"]),
         :ok <- validate_delivery_aad(aad),
         :ok <- validate_base64url_bytes(encrypted_payload["nonce"], 24),
         :ok <- validate_base64url_min_bytes(encrypted_payload["ciphertext"], 128),
         true <- maintenance_wrap["key_version"] == key_version,
         :ok <- validate_base64url_bytes(maintenance_wrap["nonce"], 24),
         :ok <- validate_base64url_min_bytes(maintenance_wrap["ciphertext"], 48) do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  def validate_encrypted_bootstrap_package(_package, _workspace_id, _key_version),
    do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_recipient_wrap(%{"nonce" => nonce, "ciphertext" => ciphertext} = wrap, _, _, _) do
    with true <- exact_keys?(wrap, ["ciphertext", "nonce"]),
         :ok <- validate_base64url_bytes(nonce, 24),
         :ok <- validate_base64url_min_bytes(ciphertext, 48) do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  defp validate_recipient_wrap(
         %{
           "delivery_mode" => "known_recipient",
           "recipient_user_id" => recipient_user_id,
           "sender_signing_public_key_material" => sender_public,
           "wraps" => wraps
         } = recipient_wrap,
         aad,
         workspace_id,
         key_version
       )
       when is_binary(recipient_user_id) and wraps == [] and is_map(sender_public) do
    with true <-
           exact_keys?(recipient_wrap, [
             "delivery_mode",
             "recipient_user_id",
             "sender_signing_public_key_material",
             "wraps"
           ]),
         true <- recipient_user_id == aad["recipient_user_id"],
         true <- aad["workspace_id"] == workspace_id,
         true <- aad["key_version_context"]["workspace_kek_version"] == key_version do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  defp validate_recipient_wrap(_, _, _, _),
    do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_delivery_aad(%{
         "delivery_mode" => "unknown_fragment",
         "recipient_user_id" => "NOT_APPLICABLE",
         "recipient_device_ids" => []
       }),
       do: :ok

  defp validate_delivery_aad(%{
         "delivery_mode" => "known_recipient",
         "recipient_user_id" => recipient_user_id,
         "recipient_device_ids" => device_ids
       })
       when is_binary(recipient_user_id) and is_list(device_ids) and device_ids != [] do
    if Enum.all?(device_ids, &is_binary/1) and Enum.uniq(device_ids) == device_ids,
      do: :ok,
      else: {:error, :invalid_encrypted_bootstrap_package}
  end

  defp validate_delivery_aad(_), do: {:error, :invalid_encrypted_bootstrap_package}

  def create_invitation(attrs) do
    create_invitation_with_retry(attrs, 0)
  end

  @max_accept_retries 3

  def accept_invitation(token_hash, user_id, user_email, requester_device_id, admission \\ nil)

  def accept_invitation(
        token_hash,
        user_id,
        user_email,
        requester_device_id,
        admission
      )
      when is_binary(requester_device_id) do
    reserve_acceptance_with_retry(
      token_hash,
      user_id,
      user_email,
      requester_device_id,
      admission,
      0
    )
  end

  def accept_invitation(
        _token_hash,
        _user_id,
        _user_email,
        _requester_device_id,
        _admission
      ),
      do: {:error, :missing_device}

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
        delivery_mode: i.delivery_mode,
        recipient_user_id: i.recipient_user_id,
        recipient_device_ids: i.recipient_device_ids,
        kek_version: i.kek_version,
        is_used: i.is_used,
        expires_at: i.expires_at,
        created_at: i.created_at
      },
      order_by: [desc: i.created_at]
    )
    |> Repo.all()
  end

  def delete_expired_invitations(now \\ DateTime.utc_now()) do
    {count, _} =
      from(i in WorkspaceInvitation,
        where: i.expires_at <= ^now
      )
      |> Repo.delete_all()

    count
  end

  def revoke_invitation(workspace_id, invitation_id) do
    revoke_invitation(workspace_id, invitation_id, nil, nil)
  end

  def revoke_invitation(workspace_id, invitation_id, actor_user_id, key_directory) do
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

          revoked = %{invitation | revoked_at: now}

          KeyDirectory.append_if_present(key_directory, %{
            kind: :workspace_invitation_revoked,
            workspace_id: workspace_id,
            actor_user_id: actor_user_id,
            actor_device_id: Map.get(key_directory || %{}, :actor_device_id),
            invitation: revoked
          })

          revoked
      end
    end)
  end

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
    Repo.transaction(
      fn ->
        workspace = lock_workspace_for_share(attrs.workspace_id)

        with :ok <- validate_invitation_creation(workspace, attrs),
             {:ok, actor_role} <- lock_actor_role(attrs.workspace_id, attrs.invited_by),
             :ok <- check_rbac_permission(actor_role, "member:invite"),
             :ok <- validate_recipient_delivery_binding(attrs),
             :ok <- validate_known_recipient_not_member(attrs),
             {:ok, target_role} <- resolve_invitation_role(attrs),
             :ok <- validate_escalation(actor_role, target_role),
             {:ok, invitation} <- insert_invitation(attrs, target_role),
             :ok <-
               KeyDirectory.append_if_present(attrs[:key_directory], %{
                 kind: :workspace_invitation_created,
                 workspace_id: invitation.workspace_id,
                 actor_user_id: attrs.invited_by,
                 actor_device_id: attrs[:actor_device_id],
                 invitee_user_id: attrs[:invitee_user_id],
                 invitation: invitation,
                 target_role: target_role
               }) do
          invitation
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end,
      isolation: :serializable
    )
    |> normalize_transaction_result()
  rescue
    e in Postgrex.Error ->
      case e.postgres.code do
        :serialization_failure -> {:error, :serialization_failure}
        _ -> reraise e, __STACKTRACE__
      end
  end

  # ── Accept Invitation Private ───────────────────

  defp reserve_acceptance_with_retry(
         _token_hash,
         _user_id,
         _user_email,
         _requester_device_id,
         _admission,
         @max_accept_retries
       ) do
    {:error, :serialization_failure}
  end

  defp reserve_acceptance_with_retry(
         token_hash,
         user_id,
         user_email,
         requester_device_id,
         admission,
         attempt
       ) do
    case reserve_acceptance(
           token_hash,
           user_id,
           user_email,
           requester_device_id,
           admission
         ) do
      {:error, :retry} ->
        reserve_acceptance_with_retry(
          token_hash,
          user_id,
          user_email,
          requester_device_id,
          admission,
          attempt + 1
        )

      other ->
        other
    end
  end

  defp reserve_acceptance(
         token_hash,
         user_id,
         user_email,
         requester_device_id,
         admission
       ) do
    Repo.transaction(
      fn ->
        invitation = find_invitation_by_hash_for_update(token_hash)
        if is_nil(invitation), do: Repo.rollback(:not_found)

        workspace = lock_workspace_for_share(invitation.workspace_id)
        if is_nil(workspace), do: Repo.rollback(:not_found)

        handle_acceptance_membership_state(
          invitation,
          workspace,
          user_id,
          user_email,
          requester_device_id,
          admission
        )
      end,
      isolation: :serializable
    )
    |> normalize_transaction_result()
  rescue
    e in Postgrex.Error ->
      case e.postgres.code do
        :serialization_failure -> {:error, :retry}
        :deadlock_detected -> {:error, :retry}
        _ -> reraise e, __STACKTRACE__
      end
  end

  defp find_invitation_by_hash_for_update(token_hash) do
    from(i in WorkspaceInvitation, where: i.token_hash == ^token_hash, lock: "FOR UPDATE")
    |> Repo.one()
  end

  defp handle_acceptance_membership_state(
         invitation,
         workspace,
         user_id,
         user_email,
         requester_device_id,
         admission
       ) do
    case {find_existing_member(invitation.workspace_id, user_id), invitation.delivery_mode} do
      {%WorkspaceMember{}, "known_recipient"} ->
        case validate_recipient_acceptance(
               invitation,
               user_id,
               user_email,
               requester_device_id
             ) do
          :ok -> Repo.rollback(:recipient_already_member)
          {:error, reason} -> Repo.rollback(reason)
        end

      {%WorkspaceMember{}, _delivery_mode} ->
        validate_existing_member_or_rollback(
          invitation,
          user_id,
          user_email,
          requester_device_id,
          workspace
        )

      {nil, _delivery_mode} ->
        reserve_new_member_acceptance(
          invitation,
          workspace,
          user_id,
          user_email,
          requester_device_id,
          admission
        )
    end
  end

  defp validate_recipient_delivery_binding(attrs) do
    Users.validate_invitation_delivery_binding(
      attrs.invited_email,
      attrs.delivery_mode,
      attrs[:recipient_user_id],
      attrs[:recipient_device_ids] || []
    )
  end

  defp validate_known_recipient_not_member(%{
         delivery_mode: "known_recipient",
         workspace_id: workspace_id,
         recipient_user_id: recipient_user_id
       }) do
    if find_existing_member(workspace_id, recipient_user_id),
      do: {:error, :recipient_already_member},
      else: :ok
  end

  defp validate_known_recipient_not_member(_attrs), do: :ok

  defp validate_existing_member_or_rollback(
         invitation,
         user_id,
         user_email,
         requester_device_id,
         workspace
       ) do
    case validate_existing_member_acceptance(
           invitation,
           user_id,
           user_email,
           requester_device_id,
           workspace
         ) do
      :ok -> build_acceptance_result(invitation, workspace)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp reserve_new_member_acceptance(
         invitation,
         workspace,
         user_id,
         user_email,
         requester_device_id,
         admission
       ) do
    with :ok <- check_invitation_validity(invitation, user_id, user_email, requester_device_id),
         :ok <- validate_known_recipient_delivery_admission(invitation, admission),
         :ok <- validate_workspace_acceptance_state(invitation, workspace),
         {:ok, target_role} <- fetch_target_role(invitation),
         {:ok, _member} <- insert_member(invitation, user_id),
         :ok <- persist_invitation_admission!(invitation, user_id, requester_device_id, admission),
         :ok <- mark_invitation_used(invitation) do
      build_acceptance_result(%{invitation | is_used: true}, workspace, target_role)
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp validate_known_recipient_delivery_admission(
         %WorkspaceInvitation{delivery_mode: "known_recipient"},
         %{recipient_delivery_attempt: %RefMD.Workspaces.InvitationDeliveryAttempt{}}
       ),
       do: :ok

  defp validate_known_recipient_delivery_admission(
         %WorkspaceInvitation{delivery_mode: "known_recipient"},
         _admission
       ),
       do: {:error, :recipient_delivery_required}

  defp validate_known_recipient_delivery_admission(_invitation, _admission), do: :ok

  defp find_existing_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: wm
    )
    |> Repo.one()
  end

  defp validate_existing_member_acceptance(
         invitation,
         user_id,
         user_email,
         requester_device_id,
         workspace
       ) do
    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, DateTime.utc_now()) != :gt ->
        {:error, :invitation_expired}

      true ->
        with :ok <-
               validate_recipient_acceptance(invitation, user_id, user_email, requester_device_id) do
          validate_workspace_acceptance_state(invitation, workspace)
        end
    end
  end

  defp check_invitation_validity(invitation, user_id, user_email, requester_device_id) do
    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      DateTime.compare(invitation.expires_at, DateTime.utc_now()) != :gt ->
        {:error, :invitation_expired}

      invitation.is_used ->
        {:error, :invitation_already_used}

      true ->
        validate_recipient_acceptance(invitation, user_id, user_email, requester_device_id)
    end
  end

  defp validate_recipient_acceptance(
         %WorkspaceInvitation{delivery_mode: "known_recipient"} = invitation,
         user_id,
         _user_email,
         requester_device_id
       ) do
    cond do
      invitation.recipient_user_id != user_id ->
        {:error, :recipient_mismatch}

      requester_device_id not in invitation.recipient_device_ids ->
        {:error, :recipient_device_mismatch}

      not Devices.user_owns_active_device?(user_id, requester_device_id) ->
        {:error, :recipient_device_revoked}

      true ->
        :ok
    end
  end

  defp validate_recipient_acceptance(
         %WorkspaceInvitation{delivery_mode: "unknown_fragment"} = invitation,
         _user_id,
         user_email,
         _requester_device_id
       ) do
    if invitation.invited_email == user_email, do: :ok, else: {:error, :email_mismatch}
  end

  defp validate_recipient_acceptance(_, _, _, _), do: {:error, :recipient_mismatch}

  defp validate_workspace_acceptance_state(invitation, workspace) do
    cond do
      RotationPolicy.kek_overdue?(workspace) ->
        {:error, :kek_rotation_in_progress}

      invitation.kek_version < workspace.min_kek_version ->
        {:error, {:invitation_kek_outdated, invitation.workspace_id}}

      invitation.role_id == nil ->
        {:error, :invitation_role_deleted}

      true ->
        :ok
    end
  end

  defp fetch_target_role(%WorkspaceInvitation{role_id: role_id, workspace_id: workspace_id})
       when is_binary(role_id) do
    case Repo.get_by(WorkspaceRole, id: role_id, workspace_id: workspace_id) do
      nil -> {:error, :invitation_role_deleted}
      role -> {:ok, role}
    end
  end

  defp fetch_target_role(_invitation), do: {:error, :invitation_role_deleted}

  defp insert_member(invitation, user_id) do
    %WorkspaceMember{}
    |> WorkspaceMember.changeset(%{
      workspace_id: invitation.workspace_id,
      user_id: user_id,
      role_id: invitation.role_id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })
    |> Repo.insert(
      on_conflict: :nothing,
      conflict_target: [:workspace_id, :user_id]
    )
    |> case do
      {:ok, member} -> {:ok, member}
      {:error, _changeset} -> {:error, :member_insert_failed}
    end
  end

  defp persist_invitation_admission!(
         invitation,
         user_id,
         requester_device_id,
         %{
           key_directory: key_directory,
           member_envelope: member_envelope
         } = admission
       )
       when is_map(member_envelope) do
    validation_context = %{
      workspace_id: invitation.workspace_id,
      invitation_id: invitation.id,
      target_user_id: user_id,
      requester_device_id: requester_device_id,
      kek_version: invitation.kek_version,
      key_directory: key_directory,
      recipient_delivery_attempt: Map.get(admission, :recipient_delivery_attempt)
    }

    case Encryption.validate_workspace_invitation_member_envelope(
           member_envelope,
           validation_context
         ) do
      {:ok, %{member_envelope_hash: member_envelope_hash}} ->
        KeyDirectory.append_if_present(
          key_directory,
          workspace_redeem_operation(
            invitation,
            user_id,
            requester_device_id,
            member_envelope_hash,
            Map.get(admission, :recipient_delivery_attempt),
            key_directory
          )
        )

        case Encryption.save_member_envelopes(invitation.workspace_id, [member_envelope]) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp persist_invitation_admission!(_, _, _, _), do: {:error, :missing_key_directory}

  defp workspace_redeem_operation(
         invitation,
         user_id,
         requester_device_id,
         member_envelope_hash,
         nil,
         key_directory
       ) do
    %{
      kind: :workspace_invitation_redeemed,
      workspace_id: invitation.workspace_id,
      redeem_authority_signing_key_id: redeem_authority_signing_key_id!(key_directory),
      invitation: invitation,
      redeemed_user_id: user_id,
      redeemed_device_id: requester_device_id,
      member_envelope_hash: member_envelope_hash
    }
  end

  defp workspace_redeem_operation(
         invitation,
         user_id,
         requester_device_id,
         member_envelope_hash,
         attempt,
         _key_directory
       ) do
    freshness = attempt.approved_artifacts["redeem_freshness_proof"]

    %{
      kind: :workspace_invitation_redeemed,
      workspace_id: invitation.workspace_id,
      actor_user_id: get_in(freshness, ["authoritative_device", "user_id"]),
      actor_device_id: get_in(freshness, ["authoritative_device", "device_id"]),
      invitation: invitation,
      redeemed_user_id: user_id,
      redeemed_device_id: requester_device_id,
      member_envelope_hash: member_envelope_hash,
      recipient_delivery_attempt: attempt
    }
  end

  defp redeem_authority_signing_key_id!(%{events: events}) when is_list(events) do
    events
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => "workspace_invitation_redeemed", "actor" => actor}}
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

  defp mark_invitation_used(invitation) do
    {1, _} =
      from(i in WorkspaceInvitation, where: i.id == ^invitation.id)
      |> Repo.update_all(set: [is_used: true])

    :ok
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
      RotationPolicy.kek_overdue?(workspace) ->
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
    RefMD.Workspaces.validate_role_assignment(actor_role, target_role)
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
        delivery_mode: attrs.delivery_mode,
        recipient_user_id: attrs[:recipient_user_id],
        recipient_device_ids: attrs[:recipient_device_ids] || [],
        kek_version: attrs.kek_version,
        bootstrap_key_commitment: attrs[:bootstrap_key_commitment],
        encrypted_bootstrap_package: attrs[:encrypted_bootstrap_package],
        bootstrap_package_hash: attrs[:bootstrap_package_hash],
        bootstrap_package_key_recipient_wrap: attrs[:bootstrap_package_key_recipient_wrap],
        bootstrap_package_key_maintenance_wrap: attrs[:bootstrap_package_key_maintenance_wrap],
        bootstrap_suite_id: attrs[:bootstrap_suite_id],
        capability_context_hash: attrs[:capability_context_hash],
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

  defp build_acceptance_result(invitation, workspace, target_role \\ nil) do
    role_name =
      cond do
        target_role != nil ->
          target_role.name

        is_nil(invitation.role_id) ->
          nil

        true ->
          case Repo.get(WorkspaceRole, invitation.role_id) do
            nil -> nil
            role -> role.name
          end
      end

    {:ok,
     %{
       status: "accepted",
       workspace_id: invitation.workspace_id,
       workspace_name: workspace.name,
       role_name: role_name,
       invitation_id: invitation.id,
       kek_version: invitation.kek_version,
       encrypted_bootstrap_package: invitation.encrypted_bootstrap_package,
       workspace_key_directory_checkpoint:
         serialize_checkpoint(
           Encryption.current_workspace_key_directory_checkpoint(invitation.workspace_id)
         )
     }}
  end

  defp serialize_checkpoint(nil), do: nil

  defp serialize_checkpoint(checkpoint) do
    %{payload: checkpoint.payload, signatures: checkpoint.signatures}
  end

  defp check_rbac_permission(role, permission) do
    perms = RefMD.Workspaces.effective_permissions(role)
    if MapSet.member?(perms, permission), do: :ok, else: {:error, :permission_denied}
  end

  defp normalize_transaction_result({:ok, {:ok, result}}), do: {:ok, result}
  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}

  defp exact_keys?(map, keys) when is_map(map),
    do: Map.keys(map) |> Enum.sort() == Enum.sort(keys)

  defp validate_base64url_bytes(value, byte_size) when is_binary(value) do
    Encoding.decode_base64url!(value, byte_size)
    :ok
  rescue
    ArgumentError -> {:error, :invalid_encrypted_bootstrap_package}
  end

  defp validate_base64url_bytes(_, _), do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_base64url_min_bytes(value, min_byte_size) when is_binary(value) do
    bytes = Encoding.decode_base64url!(value)

    if byte_size(bytes) >= min_byte_size,
      do: :ok,
      else: {:error, :invalid_encrypted_bootstrap_package}
  rescue
    ArgumentError -> {:error, :invalid_encrypted_bootstrap_package}
  end

  defp validate_base64url_min_bytes(_, _), do: {:error, :invalid_encrypted_bootstrap_package}
end
