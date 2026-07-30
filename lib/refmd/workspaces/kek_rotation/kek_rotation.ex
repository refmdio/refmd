defmodule RefMD.Workspaces.KekRotation do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Encryption

  alias RefMD.Encryption.{
    Members,
    RotationPolicy,
    WorkspaceEncryptedKey,
    WorkspaceMemberEnvelope
  }

  alias RefMD.Encryption.Workspaces, as: EncryptionWorkspaces
  alias RefMD.Encryption.Wraps.Precommit
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces.KekRotation.DeletionProofs
  alias RefMD.Workspaces.KekRotation.Directory

  alias RefMD.Workspaces.{
    GuestInvitation,
    Workspace,
    WorkspaceDeviceWipeRequirement,
    WorkspaceInvitation,
    WorkspaceMember,
    WorkspaceRole
  }

  def mark_kek_rotation_needed(workspace_ids, initiator_user_id) when workspace_ids != [] do
    count =
      Enum.reduce(workspace_ids, 0, fn workspace_id, count ->
        initiator =
          if rotation_initiator_eligible?(workspace_id, initiator_user_id),
            do: initiator_user_id,
            else: next_rotation_initiator(workspace_id)

        case initiator do
          nil ->
            count

          user_id ->
            {updated, _} =
              from(w in Workspace,
                where: w.id == ^workspace_id and w.needs_kek_rotation == false
              )
              |> Repo.update_all(
                set: [needs_kek_rotation: true, kek_rotation_initiator_user_id: user_id]
              )

            count + updated
        end
      end)

    {count, nil}
  end

  def mark_kek_rotation_needed([], _initiator_user_id), do: {0, nil}

  def rotation_initiator_eligible?(workspace_id, user_id)
      when is_binary(workspace_id) and is_binary(user_id) do
    workspace_id
    |> eligible_rotation_initiators_query()
    |> where([wm, _role, _user, _device], wm.user_id == ^user_id)
    |> Repo.exists?()
  end

  def rotation_initiator_eligible?(_, _), do: false

  def next_rotation_initiator(workspace_id) when is_binary(workspace_id) do
    workspace_id
    |> eligible_rotation_initiators_query()
    |> select([wm, _role, _user, _device], wm.user_id)
    |> limit(1)
    |> Repo.one()
  end

  def next_rotation_initiator(_), do: nil

  def mark_dek_rotation_needed(workspace_ids, "security") when workspace_ids != [] do
    from(d in RefMD.Documents.Document, where: d.workspace_id in ^workspace_ids)
    |> Repo.update_all(set: [needs_dek_rotation: true, dek_rotation_reason: "security"])
  end

  def mark_dek_rotation_needed(workspace_ids, "membership_change") when workspace_ids != [] do
    from(d in RefMD.Documents.Document,
      where:
        d.workspace_id in ^workspace_ids and
          (is_nil(d.dek_rotation_reason) or d.dek_rotation_reason != "security")
    )
    |> Repo.update_all(set: [needs_dek_rotation: true, dek_rotation_reason: "membership_change"])
  end

  def mark_dek_rotation_needed([], reason)
      when reason in ["security", "membership_change"],
      do: {0, nil}

  def mark_membership_rotation_needed!(workspace_id, initiator_user_id) do
    case mark_kek_rotation_needed([workspace_id], initiator_user_id) do
      {1, _} -> :ok
      {0, _} -> assert_rotation_already_pending!(workspace_id)
    end

    mark_dek_rotation_needed([workspace_id], "membership_change")
    :ok
  rescue
    _ -> Repo.rollback(:rotation_mark_failed)
  end

  defp assert_rotation_already_pending!(workspace_id) do
    case Repo.get(Workspace, workspace_id) do
      %{needs_kek_rotation: true} -> :ok
      _ -> Repo.rollback(:rotation_initiator_missing)
    end
  end

  def prepare_start!(workspace_id, initiator_user_id) do
    workspace =
      from(w in Workspace,
        where: w.id == ^workspace_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    cond do
      workspace == nil ->
        Repo.rollback(:not_found)

      not rotation_initiator_eligible?(workspace_id, initiator_user_id) ->
        Repo.rollback(:forbidden)

      workspace.needs_kek_rotation and
          Directory.rotation_started?(workspace, workspace.current_kek_version + 1) ->
        Repo.rollback(:kek_rotation_already_in_progress)

      true ->
        workspace
    end
  end

  def apply_start!(workspace_id, initiator_user_id, rotation_id, new_kek_version) do
    prepare_start!(workspace_id, initiator_user_id)

    from(w in Workspace, where: w.id == ^workspace_id)
    |> Repo.update_all(
      set: [
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: initiator_user_id,
        current_kek_rotation_id: rotation_id,
        pending_kek_version: new_kek_version,
        kek_rotation_completed_event_hash: nil
      ]
    )

    Repo.get!(Workspace, workspace_id)
  end

  def prepare_completion!(command, actor_user_id, actor_device_id) do
    workspace = lock_rotation_workspace!(command, actor_user_id, :started)

    unless command["old_key_version"] == workspace.current_kek_version and
             command["new_key_version"] == workspace.pending_kek_version and
             is_list(command["device_wrap_precommits"]) and
             is_list(command["member_envelope_precommits"]) and
             is_list(command["workspace_invitation_updates"]) and
             is_list(command["guest_invitation_updates"]),
           do: raise(ArgumentError, "kek_rotation_completion_command_invalid")

    checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace.id)
    actor = Repo.get!(Device, actor_device_id)
    sender = wrap_sender!(workspace.id, actor_user_id, actor, checkpoint)

    device_wraps =
      validate_device_wrap_precommits!(workspace, command, sender, checkpoint)

    member_envelopes =
      validate_member_envelope_precommits!(workspace, command, sender, checkpoint)

    validate_invitation_updates!(
      WorkspaceInvitation,
      workspace,
      command["workspace_invitation_updates"],
      command["old_key_version"],
      command["new_key_version"]
    )

    validate_invitation_updates!(
      GuestInvitation,
      workspace,
      command["guest_invitation_updates"],
      command["old_key_version"],
      command["new_key_version"]
    )

    %{
      workspace: workspace,
      device_wraps: device_wraps,
      member_envelopes: member_envelopes
    }
  end

  def prepare_old_key_deletion!(command, actor_user_id) do
    workspace = lock_rotation_workspace!(command, actor_user_id, :completed)

    unless command["old_key_version"] == workspace.min_kek_version and
             is_map(command["deletion_manifest"]) and
             is_list(command["device_key_deletion_proofs"]) and
             is_list(command["wipe_required_device_ids"]),
           do: raise(ArgumentError, "kek_rotation_old_key_deletion_command_invalid")

    deletion_context =
      DeletionProofs.validate!(
        workspace.id,
        command["old_key_version"],
        workspace.kek_rotation_completed_event_hash,
        command["device_key_deletion_proofs"],
        command["wipe_required_device_ids"]
      )

    :ok =
      Directory.validate_old_key_deletion_manifest!(
        workspace,
        command["deletion_manifest"],
        deletion_context
      )

    %{workspace: workspace, deletion_context: deletion_context}
  end

  def apply_completion!(verified, completed_event_hash) do
    p = verified.prepared
    command = p.command
    workspace = lock_rotation_workspace!(command, p.actor_user_id, :started)
    insert_completion_wraps!(verified)
    apply_invitation_updates!(WorkspaceInvitation, command["workspace_invitation_updates"])
    apply_invitation_updates!(GuestInvitation, command["guest_invitation_updates"])
    reject_old_kek_document_references!(workspace.id, command["new_key_version"])

    from(w in Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(
      set: [
        current_kek_version: command["new_key_version"],
        needs_kek_rotation: false,
        kek_rotation_due_at: RotationPolicy.next_kek_due_at(),
        kek_rotation_completed_event_hash: completed_event_hash
      ]
    )

    Repo.get!(Workspace, workspace.id)
  end

  def apply_old_key_deletion!(command, actor_user_id, deleted_event_hash) do
    workspace = lock_rotation_workspace!(command, actor_user_id, :completed)
    old_key_version = command["old_key_version"]

    persist_workspace_device_wipe_requirements!(
      workspace.id,
      workspace.current_kek_version,
      command["wipe_required_device_ids"]
    )

    from(k in WorkspaceEncryptedKey,
      where: k.workspace_id == ^workspace.id and k.key_version == ^old_key_version
    )
    |> Repo.delete_all()

    from(e in WorkspaceMemberEnvelope,
      where: e.workspace_id == ^workspace.id and e.key_version == ^old_key_version
    )
    |> Repo.delete_all()

    Directory.persist_old_key_deletion_evidence!(
      workspace,
      deleted_event_hash,
      command["deletion_manifest"],
      command["device_key_deletion_proofs"],
      command["wipe_required_device_ids"]
    )

    from(w in Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(
      set: [
        min_kek_version: workspace.current_kek_version,
        current_kek_rotation_id: nil,
        pending_kek_version: nil,
        kek_rotation_completed_event_hash: nil,
        kek_rotation_initiator_user_id: nil
      ]
    )

    Repo.get!(Workspace, workspace.id)
  end

  defp lock_rotation_workspace!(command, actor_user_id, expected_state) do
    workspace =
      from(w in Workspace, where: w.id == ^command["workspace_id"], lock: "FOR UPDATE")
      |> Repo.one()

    validate_rotation_workspace!(workspace, command, actor_user_id, expected_state)
    workspace
  end

  defp validate_rotation_workspace!(nil, _command, _actor_user_id, _expected_state),
    do: raise(ArgumentError, "workspace_not_found")

  defp validate_rotation_workspace!(workspace, command, actor_user_id, expected_state) do
    checks = [
      {rotation_initiator_eligible?(workspace.id, actor_user_id), "forbidden"},
      {workspace.current_kek_rotation_id == command["rotation_id"], "kek_rotation_id_mismatch"},
      {expected_state != :started or workspace.needs_kek_rotation,
       "kek_rotation_not_in_progress"},
      {expected_state != :completed or
         (not workspace.needs_kek_rotation and
            not is_nil(workspace.kek_rotation_completed_event_hash)),
       "kek_rotation_not_completed"}
    ]

    Enum.each(checks, fn {valid?, error} ->
      unless valid?, do: raise(ArgumentError, error)
    end)
  end

  defp validate_device_wrap_precommits!(workspace, command, sender, checkpoint) do
    expected_devices =
      from(wm in WorkspaceMember,
        join: u in User,
        on: u.id == wm.user_id,
        join: d in Device,
        on: d.user_id == wm.user_id,
        where:
          wm.workspace_id == ^workspace.id and u.account_type != "guest" and is_nil(d.revoked_at) and
            is_nil(d.identity_wipe_required_at),
        order_by: [asc: wm.user_id, asc: d.id],
        select: {wm.user_id, d}
      )
      |> Repo.all()

    entries = command["device_wrap_precommits"]

    unless Enum.map(entries, &{&1["target_user_id"], &1["target_device_id"]}) ==
             Enum.map(expected_devices, fn {user_id, device} -> {user_id, device.id} end),
           do: raise(ArgumentError, "kek_rotation_device_wrap_inventory_invalid")

    Enum.zip(entries, expected_devices)
    |> Enum.map(fn {entry, {target_user_id, device}} ->
      material = device.hybrid_encryption_public_key_material
      key_id = HybridEncryptionMaterial.compute_key_id!(material)

      unless key_id == device.encryption_key_id,
        do: raise(ArgumentError, "kek_rotation_device_encryption_key_invalid")

      expected = %{
        purpose: "workspace_device_kek_wrap",
        resource: %{
          "workspace_id" => workspace.id,
          "target_user_id" => target_user_id,
          "target_device_id" => device.id,
          "kek_version" => command["new_key_version"]
        },
        sender: sender,
        recipient: %{
          "recipient_kind" => "device",
          "user_id" => target_user_id,
          "device_id" => device.id,
          "encryption_key_id" => key_id,
          "key_scope_kind" => "workspace",
          "key_scope_id" => workspace.id,
          "key_checkpoint_sequence" => checkpoint.sequence,
          "key_checkpoint_hash" => checkpoint.checkpoint_hash
        },
        event_scope: %{"scope_kind" => "workspace", "scope_id" => workspace.id}
      }

      Map.merge(Precommit.validate!(entry["wrap"], expected), %{
        target_user_id: target_user_id,
        target_device_id: device.id,
        sender_device_id: sender["device_id"]
      })
    end)
  end

  defp validate_member_envelope_precommits!(workspace, command, sender, checkpoint) do
    expected_members =
      from(wm in WorkspaceMember,
        join: u in User,
        on: u.id == wm.user_id,
        where: wm.workspace_id == ^workspace.id and u.account_type != "guest",
        order_by: [asc: wm.user_id],
        select: wm.user_id
      )
      |> Repo.all()

    entries = command["member_envelope_precommits"]

    unless Enum.map(entries, & &1["target_user_id"]) == expected_members,
      do: raise(ArgumentError, "kek_rotation_member_envelope_inventory_invalid")

    Enum.map(entries, fn entry ->
      exact_member_precommit_keys!(entry)
      target_user_id = entry["target_user_id"]
      identity = Encryption.get_user_identity_public_key(target_user_id)
      material = identity.hybrid_encryption_public_key_material
      key_id = HybridEncryptionMaterial.compute_key_id!(material)
      material_hash = hash(material)

      expected = %{
        workspace_id: workspace.id,
        target_user_id: target_user_id,
        kek_version: command["new_key_version"],
        target_identity_encryption_key_id: key_id,
        target_identity_key_material_hash: material_hash,
        checkpoint_sequence: checkpoint.sequence,
        checkpoint_hash: checkpoint.checkpoint_hash,
        purpose: "workspace_member_kek_wrap",
        resource: %{
          "workspace_id" => workspace.id,
          "target_user_id" => target_user_id,
          "kek_version" => command["new_key_version"]
        },
        sender: sender,
        recipient: %{
          "recipient_kind" => "user_identity",
          "user_id" => target_user_id,
          "encryption_key_id" => key_id,
          "key_scope_kind" => "workspace",
          "key_scope_id" => workspace.id,
          "key_checkpoint_sequence" => checkpoint.sequence,
          "key_checkpoint_hash" => checkpoint.checkpoint_hash
        },
        event_scope: %{"scope_kind" => "workspace", "scope_id" => workspace.id}
      }

      unless Map.take(
               entry,
               ~w(protocol version workspace_id target_user_id kek_version target_identity_encryption_key_id target_identity_key_material_hash authorization_key_directory_checkpoint_sequence authorization_key_directory_checkpoint_hash)
             ) ==
               %{
                 "protocol" => "refmd.workspace-member-envelope",
                 "version" => 1,
                 "workspace_id" => workspace.id,
                 "target_user_id" => target_user_id,
                 "kek_version" => command["new_key_version"],
                 "target_identity_encryption_key_id" => key_id,
                 "target_identity_key_material_hash" => material_hash,
                 "authorization_key_directory_checkpoint_sequence" => checkpoint.sequence,
                 "authorization_key_directory_checkpoint_hash" => checkpoint.checkpoint_hash
               },
             do: raise(ArgumentError, "kek_rotation_member_envelope_precommit_invalid")

      derived = Precommit.validate!(entry["wrap"], expected)
      Precommit.member_envelope_commitment(entry, expected, derived)
    end)
  end

  defp wrap_sender!(workspace_id, actor_user_id, actor, checkpoint) do
    signing_key_id = Signature.compute_signing_key_id!(actor.hybrid_signing_public_key_material)

    unless actor.user_id == actor_user_id and signing_key_id == actor.signing_key_id,
      do: raise(ArgumentError, "kek_rotation_actor_key_invalid")

    %{
      "signer_kind" => "device",
      "user_id" => actor_user_id,
      "device_id" => actor.id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint.checkpoint_hash
    }
  end

  defp exact_member_precommit_keys!(entry) do
    keys =
      ~w(authorization_key_directory_checkpoint_hash authorization_key_directory_checkpoint_sequence kek_version protocol target_identity_encryption_key_id target_identity_key_material_hash target_user_id version workspace_id wrap)

    unless is_map(entry) and Enum.sort(Map.keys(entry)) == keys,
      do: raise(ArgumentError, "kek_rotation_member_envelope_precommit_keys_invalid")
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp validate_invitation_updates!(schema, workspace, updates, old_key_version, new_key_version) do
    now = DateTime.utc_now()

    expected =
      from(i in schema,
        where:
          i.workspace_id == ^workspace.id and is_nil(i.revoked_at) and i.expires_at > ^now and
            i.kek_version == ^old_key_version,
        order_by: [asc: i.id],
        select: i
      )
      |> maybe_exclude_used(schema)
      |> maybe_workspace_scope(schema)
      |> Repo.all()

    actual = Enum.map(updates, &invitation_update_id!(schema, &1))

    unless actual == Enum.map(expected, & &1.id),
      do: raise(ArgumentError, "kek_rotation_invitation_inventory_invalid")

    Enum.zip(updates, expected)
    |> Enum.each(fn {update, invitation} ->
      validate_invitation_update!(schema, workspace, update, invitation, new_key_version)
    end)
  end

  defp maybe_exclude_used(query, WorkspaceInvitation), do: where(query, [i], i.is_used == false)

  defp maybe_exclude_used(query, GuestInvitation),
    do: where(query, [i], i.redemption_count < i.max_redemptions)

  defp maybe_workspace_scope(query, WorkspaceInvitation), do: query

  defp maybe_workspace_scope(query, GuestInvitation),
    do: where(query, [i], i.scope_kind == "workspace")

  defp validate_invitation_update!(schema, workspace, update, invitation, new_key_version) do
    package = update["encrypted_bootstrap_package"]
    maintenance_wrap = update["bootstrap_package_key_maintenance_wrap"]
    aad = package["aad"]
    context = aad["key_version_context"]

    validate_invitation_update_shape!(schema, update, package, aad, context, maintenance_wrap)
    validate_invitation_update_hashes!(update, invitation, package, maintenance_wrap)

    validate_invitation_update_version_binding!(
      update,
      workspace,
      package,
      maintenance_wrap,
      context,
      new_key_version
    )

    validate_invitation_scope!(schema, update, invitation, aad)
  end

  defp validate_invitation_update_shape!(schema, update, package, aad, context, maintenance_wrap) do
    unless exact_invitation_update_keys?(schema, update) and is_map(package) and is_map(aad) and
             is_map(context) and is_map(maintenance_wrap),
           do: raise(ArgumentError, "kek_rotation_invitation_update_invalid")
  end

  defp validate_invitation_update_hashes!(update, invitation, package, maintenance_wrap) do
    unless update["previous_bootstrap_package_hash"] == invitation.bootstrap_package_hash and
             update["bootstrap_package_hash"] == hash(package) and
             update["bootstrap_package_key_maintenance_wrap"] ==
               package["package_key_maintenance_wrap"] and
             update["bootstrap_package_key_maintenance_wrap_hash"] == hash(maintenance_wrap),
           do: raise(ArgumentError, "kek_rotation_invitation_update_invalid")
  end

  defp validate_invitation_update_version_binding!(
         update,
         workspace,
         package,
         maintenance_wrap,
         context,
         new_key_version
       ) do
    unless update["kek_version"] == new_key_version and
             update["bootstrap_suite_id"] == package["suite_id"] and
             update["key_version_context"] == context and
             context["workspace_kek_version"] == new_key_version and
             package["workspace_id"] == workspace.id and
             package["key_version"] == new_key_version and
             maintenance_wrap["key_version"] == new_key_version,
           do: raise(ArgumentError, "kek_rotation_invitation_update_invalid")
  end

  defp exact_invitation_update_keys?(WorkspaceInvitation, update) do
    Enum.sort(Map.keys(update)) ==
      ~w(bootstrap_package_hash bootstrap_package_key_maintenance_wrap bootstrap_package_key_maintenance_wrap_hash bootstrap_suite_id encrypted_bootstrap_package invitation_id kek_version key_version_context previous_bootstrap_package_hash)
  end

  defp exact_invitation_update_keys?(GuestInvitation, update) do
    Enum.sort(Map.keys(update)) ==
      ~w(bootstrap_package_hash bootstrap_package_key_maintenance_wrap bootstrap_package_key_maintenance_wrap_hash bootstrap_suite_id encrypted_bootstrap_package guest_invitation_id kek_version key_version_context previous_bootstrap_package_hash scope_id scope_kind)
  end

  defp validate_invitation_scope!(WorkspaceInvitation, update, invitation, aad) do
    unless update["invitation_id"] == invitation.id and aad["invitation_id"] == invitation.id,
      do: raise(ArgumentError, "kek_rotation_invitation_scope_invalid")
  end

  defp validate_invitation_scope!(GuestInvitation, update, invitation, aad) do
    unless update["guest_invitation_id"] == invitation.id and
             update["scope_kind"] == invitation.scope_kind and
             update["scope_id"] == invitation.scope_id and
             aad["guest_invitation_id"] == invitation.id and
             aad["scope_kind"] == invitation.scope_kind and aad["scope_id"] == invitation.scope_id,
           do: raise(ArgumentError, "kek_rotation_invitation_scope_invalid")
  end

  defp invitation_update_id!(WorkspaceInvitation, update), do: update["invitation_id"]
  defp invitation_update_id!(GuestInvitation, update), do: update["guest_invitation_id"]

  defp insert_completion_wraps!(verified) do
    p = verified.prepared
    scope = verified.scope
    checkpoint = scope["candidate_key_directory_checkpoint_payload"]
    covered = checkpoint["covered_event_head"]
    pq = pq_wrap_authorizations(scope, verified.effect_authorizations)
    device_count = length(p.business.device_wraps)

    p.business.device_wraps
    |> Enum.with_index()
    |> Enum.each(fn {precommit, index} ->
      event = Enum.at(scope["candidate_key_directory_effects"], index + 1)
      signature = Enum.at(pq, index)["signature"]
      wrap = finalize_precommit_wrap(precommit.wrap, event, scope, covered, signature)

      attrs =
        EncryptionWorkspaces.build_device_key_wrap_attrs!(wrap, %{
          workspace_id: p.workspace_id,
          user_id: precommit.target_user_id,
          device_id: precommit.target_device_id,
          sender_device_id: precommit.sender_device_id,
          key_version: p.command["new_key_version"],
          is_active: true
        })

      EncryptionWorkspaces.insert_compound_device_key_wrap!(attrs)
    end)

    p.business.member_envelopes
    |> Enum.with_index()
    |> Enum.each(fn {precommit, index} ->
      event = Enum.at(scope["candidate_key_directory_effects"], 1 + device_count + index)
      signature = Enum.at(pq, device_count + index)["signature"]
      wrap = finalize_precommit_wrap(precommit.wrap, event, scope, covered, signature)

      attrs =
        wrap
        |> Members.build_member_envelope_attrs!(%{
          workspace_id: p.workspace_id,
          target_user_id: precommit.precommit["target_user_id"],
          sender_device_id: p.actor_device_id,
          key_version: p.command["new_key_version"]
        })
        |> then(&Members.prepare_member_envelope_record_attrs!(p.workspace_id, &1))

      Members.insert_compound_member_envelope!(attrs)
    end)
  end

  defp pq_wrap_authorizations(scope, authorizations) do
    scope["effect_signature_requirements"]
    |> Enum.zip(authorizations)
    |> Enum.filter(fn {requirement, _authorization} ->
      requirement["authorization_kind"] == "pq_wrap"
    end)
    |> Enum.map(&elem(&1, 1))
  end

  defp finalize_precommit_wrap(wrap, event, scope, covered, signature) do
    wrap
    |> Map.put("event", %{
      "wrap_event_sequence" => event["event_payload"]["sequence"],
      "wrap_event_hash" => event["event_hash"],
      "wrap_event_body_hash" => hash(event["event_payload"]["body"])
    })
    |> Map.put("operation_checkpoint", %{
      "checkpoint_sequence" => scope["candidate_key_directory_checkpoint_payload"]["sequence"],
      "checkpoint_hash" => scope["candidate_key_directory_checkpoint_hash"],
      "covered_event_head_sequence" => covered["head_sequence"],
      "covered_event_head_hash" => covered["head_hash"]
    })
    |> Map.put("transcript_hash", signature["transcript_hash"])
    |> Map.put("signature", signature)
  end

  defp apply_invitation_updates!(schema, updates) do
    Enum.each(updates, fn update ->
      id = invitation_update_id!(schema, update)
      invitation = Repo.get!(schema, id)

      invitation
      |> Ecto.Changeset.change(%{
        kek_version: update["kek_version"],
        encrypted_bootstrap_package: update["encrypted_bootstrap_package"],
        bootstrap_package_hash: update["bootstrap_package_hash"],
        bootstrap_package_key_maintenance_wrap: update["bootstrap_package_key_maintenance_wrap"],
        bootstrap_suite_id: update["bootstrap_suite_id"]
      })
      |> Repo.update!()
    end)
  end

  defp eligible_rotation_initiators_query(workspace_id) do
    from(wm in WorkspaceMember,
      join: role in WorkspaceRole,
      on: role.id == wm.role_id and role.workspace_id == wm.workspace_id,
      join: user in User,
      on: user.id == wm.user_id,
      join: device in Device,
      on: device.user_id == wm.user_id,
      where:
        wm.workspace_id == ^workspace_id and user.account_type != "guest" and
          role.base_role in ["owner", "admin"] and is_nil(device.revoked_at) and
          is_nil(device.identity_wipe_required_at),
      order_by: [
        asc: fragment("CASE ? WHEN 'owner' THEN 0 ELSE 1 END", role.base_role),
        asc: wm.user_id
      ]
    )
  end

  def list_workspaces_needing_kek_rotation do
    from(w in Workspace,
      where: w.needs_kek_rotation == true,
      select: %{
        workspace_id: w.id,
        kek_rotation_initiator_user_id: w.kek_rotation_initiator_user_id,
        current_kek_version: w.current_kek_version,
        rotation_id: w.current_kek_rotation_id,
        pending_kek_version: w.pending_kek_version
      }
    )
    |> Repo.all()
  end

  def rotation_deletion_evidences_by_event_hash(event_hashes) when is_list(event_hashes) do
    from(e in RefMD.Workspaces.WorkspaceKekRotationDeletionEvidence,
      where: e.old_key_deleted_event_hash in ^event_hashes
    )
    |> Repo.all()
    |> Map.new(&{&1.old_key_deleted_event_hash, &1})
  end

  def wipe_requirement(workspace_id, device_id) do
    with %WorkspaceDeviceWipeRequirement{} = requirement <-
           oldest_wipe_requirement(workspace_id, device_id),
         %RefMD.Workspaces.WorkspaceKekRotationDeletionEvidence{} = evidence <-
           wipe_evidence(workspace_id, device_id, requirement.required_kek_version) do
      {:ok,
       %{
         workspace_id: workspace_id,
         required_kek_version: requirement.required_kek_version,
         old_key_version: evidence.old_key_version,
         rotation_completed_event_hash:
           evidence.deletion_manifest["rotation_completed_event_hash"],
         deleted_secret_ids_hash: evidence.deletion_manifest["deleted_secret_ids_hash"]
       }}
    else
      _ -> {:error, :wipe_requirement_not_found}
    end
  end

  def acknowledge_wipe(workspace_id, device_id, proof) when is_map(proof) do
    Repo.transaction(fn ->
      requirement =
        from(r in WorkspaceDeviceWipeRequirement,
          where: r.workspace_id == ^workspace_id and r.device_id == ^device_id,
          order_by: [asc: r.required_kek_version],
          limit: 1,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      if is_nil(requirement), do: Repo.rollback(:wipe_requirement_not_found)

      evidence =
        wipe_evidence(workspace_id, device_id, requirement.required_kek_version) ||
          Repo.rollback(:wipe_requirement_not_found)

      :ok =
        DeletionProofs.validate_kek_ack!(
          workspace_id,
          evidence.old_key_version,
          evidence.deletion_manifest["rotation_completed_event_hash"],
          device_id,
          proof
        )

      Repo.delete!(requirement)
      :ok
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_deletion_proof}
  end

  def acknowledge_wipe(_, _, _), do: {:error, :invalid_deletion_proof}

  defp wipe_evidence(workspace_id, device_id, required_kek_version) do
    from(e in RefMD.Workspaces.WorkspaceKekRotationDeletionEvidence,
      where: e.workspace_id == ^workspace_id and e.old_key_version == ^(required_kek_version - 1),
      order_by: [desc: e.inserted_at]
    )
    |> Repo.all()
    |> Enum.find(&(device_id in &1.wipe_required_device_ids))
  end

  defp persist_workspace_device_wipe_requirements!(_workspace_id, _required_kek_version, []),
    do: :ok

  defp persist_workspace_device_wipe_requirements!(
         workspace_id,
         required_kek_version,
         device_ids
       ) do
    now = DateTime.utc_now()

    rows =
      device_ids
      |> Enum.uniq()
      |> Enum.map(fn device_id ->
        %{
          workspace_id: workspace_id,
          device_id: device_id,
          required_kek_version: required_kek_version,
          reason: "kek_rotation_deletion_proof_missing",
          required_at: now,
          inserted_at: now
        }
      end)

    Repo.insert_all(WorkspaceDeviceWipeRequirement, rows,
      on_conflict: :nothing,
      conflict_target: [:workspace_id, :device_id, :required_kek_version]
    )

    :ok
  end

  defp oldest_wipe_requirement(workspace_id, device_id) do
    from(r in WorkspaceDeviceWipeRequirement,
      where: r.workspace_id == ^workspace_id and r.device_id == ^device_id,
      order_by: [asc: r.required_kek_version],
      limit: 1
    )
    |> Repo.one()
  end

  defp reject_old_kek_document_references!(workspace_id, new_kek_version) do
    old_reference_exists? =
      from(k in RefMD.Encryption.DocumentEncryptedKey,
        join: d in RefMD.Documents.Document,
        on: d.id == k.document_id,
        where:
          d.workspace_id == ^workspace_id and
            k.kek_version < ^new_kek_version,
        select: 1,
        limit: 1
      )
      |> Repo.exists?()

    if old_reference_exists?, do: Repo.rollback(:old_key_references_remaining)
  end
end
