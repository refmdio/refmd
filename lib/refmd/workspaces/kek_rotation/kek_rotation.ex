defmodule RefMD.Workspaces.KekRotation do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Repo
  alias RefMD.Workspaces.KekRotation.Directory
  alias RefMD.Workspaces.{Workspace, WorkspaceDeviceWipeRequirement}

  def mark_kek_rotation_needed(workspace_ids, initiator_user_id) when workspace_ids != [] do
    from(w in Workspace,
      where: w.id in ^workspace_ids and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [needs_kek_rotation: true, kek_rotation_initiator_user_id: initiator_user_id]
    )
  end

  def mark_kek_rotation_needed([], _initiator_user_id), do: {0, nil}

  def mark_dek_rotation_needed(workspace_ids) when workspace_ids != [] do
    from(d in RefMD.Documents.Document,
      where: d.workspace_id in ^workspace_ids and d.needs_dek_rotation == false
    )
    |> Repo.update_all(set: [needs_dek_rotation: true])
  end

  def mark_dek_rotation_needed([]), do: {0, nil}

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

        workspace.needs_kek_rotation ->
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
      conflict_target: [:workspace_id, :device_id]
    )

    :ok
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
