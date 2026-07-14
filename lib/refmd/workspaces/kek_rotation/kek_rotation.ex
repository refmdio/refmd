defmodule RefMD.Workspaces.KekRotation do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Devices.Device
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces.KekRotation.DeletionProofs
  alias RefMD.Workspaces.KekRotation.Directory

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceDeviceWipeRequirement,
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

  def start_kek_rotation(workspace_id, initiator_user_id, opts \\ []) do
    events = Keyword.get(opts, :workspace_key_directory_events)
    checkpoint = Keyword.get(opts, :workspace_key_directory_checkpoint)

    Repo.transaction(fn ->
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
          Directory.append_start!(workspace, events, checkpoint)

          from(w in Workspace, where: w.id == ^workspace_id)
          |> Repo.update_all(
            set: [
              needs_kek_rotation: true,
              kek_rotation_initiator_user_id: initiator_user_id
            ]
          )

          Repo.get!(Workspace, workspace_id)
      end
    end)
    |> case do
      {:ok, workspace} -> {:ok, workspace}
      {:error, reason} -> {:error, reason}
    end
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

  def prepare_kek_rotation_completion(workspace_id, new_kek_version, opts \\ []) do
    envelope_checks = Keyword.get(opts, :envelope_checks, fn -> :ok end)

    workspace =
      from(w in Workspace,
        where: w.id == ^workspace_id
      )
      |> Repo.one()

    cond do
      workspace == nil ->
        {:error, :not_found}

      not workspace.needs_kek_rotation ->
        {:error, :not_in_rotation}

      workspace.current_kek_version >= new_kek_version ->
        {:error, :version_not_monotonic}

      true ->
        case envelope_checks.() do
          :ok ->
            {:ok, Directory.completion_manifest_materials(workspace, new_kek_version)}

          {:error, reason} ->
            {:error, reason}
        end
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def complete_kek_rotation(workspace_id, new_kek_version, opts \\ []) do
    envelope_checks = Keyword.get(opts, :envelope_checks, fn -> :ok end)
    workspace_events = Keyword.get(opts, :workspace_key_directory_events)
    workspace_checkpoint = Keyword.get(opts, :workspace_key_directory_checkpoint)
    deletion_proofs = Keyword.get(opts, :device_key_deletion_proofs, [])
    wipe_required_device_ids = Keyword.get(opts, :wipe_required_device_ids, [])

    Repo.transaction(fn ->
      workspace =
        from(w in Workspace,
          where: w.id == ^workspace_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      cond do
        workspace == nil ->
          Repo.rollback(:not_found)

        not workspace.needs_kek_rotation ->
          Repo.rollback(:not_in_rotation)

        workspace.current_kek_version >= new_kek_version ->
          Repo.rollback(:version_not_monotonic)

        true ->
          apply_rotation_completion(
            workspace,
            new_kek_version,
            envelope_checks,
            workspace_events,
            workspace_checkpoint,
            deletion_proofs,
            wipe_required_device_ids
          )
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def list_workspaces_needing_kek_rotation do
    from(w in Workspace,
      where: w.needs_kek_rotation == true,
      select: %{
        workspace_id: w.id,
        initiator_user_id: w.kek_rotation_initiator_user_id,
        current_kek_version: w.current_kek_version
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

  defp apply_rotation_completion(
         workspace,
         new_kek_version,
         envelope_checks,
         workspace_events,
         workspace_checkpoint,
         deletion_proofs,
         wipe_required_device_ids
       ) do
    case envelope_checks.() do
      :ok ->
        Directory.append_completion!(
          workspace,
          new_kek_version,
          workspace_events,
          workspace_checkpoint,
          deletion_proofs,
          wipe_required_device_ids
        )

        persist_workspace_device_wipe_requirements!(
          workspace.id,
          new_kek_version,
          wipe_required_device_ids
        )

        reject_old_kek_document_references!(workspace.id, new_kek_version)

        from(k in RefMD.Encryption.WorkspaceEncryptedKey,
          where:
            k.workspace_id == ^workspace.id and
              k.key_version < ^new_kek_version
        )
        |> Repo.delete_all()

        from(e in RefMD.Encryption.WorkspaceMemberEnvelope,
          where:
            e.workspace_id == ^workspace.id and
              e.key_version < ^new_kek_version
        )
        |> Repo.delete_all()

        from(w in Workspace, where: w.id == ^workspace.id)
        |> Repo.update_all(
          set: [
            current_kek_version: new_kek_version,
            min_kek_version: new_kek_version,
            needs_kek_rotation: false,
            kek_rotation_due_at: RotationPolicy.next_kek_due_at(),
            kek_rotation_initiator_user_id: nil
          ]
        )

        :ok

      {:error, reason} ->
        Repo.rollback(reason)
    end
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
