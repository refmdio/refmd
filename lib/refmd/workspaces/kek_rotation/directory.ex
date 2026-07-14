defmodule RefMD.Workspaces.KekRotation.Directory do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Encoding, Hash, JCS}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces.KekRotation.DeletionProofs

  alias RefMD.Workspaces.WorkspaceKekRotationDeletionEvidence

  def rotation_started?(workspace, new_kek_version) when is_integer(new_kek_version) do
    rotation_started_event(workspace.id, workspace.current_kek_version, new_kek_version) != nil
  end

  def completion_manifest_materials(workspace, new_kek_version)
      when is_integer(new_kek_version) do
    old_kek_version = workspace.current_kek_version

    started_event =
      latest_rotation_started_event!(
        workspace.id,
        old_kek_version,
        new_kek_version
      )

    current_sequence = current_workspace_event_sequence!(workspace.id)
    completed_sequence = current_sequence + 1
    deleted_sequence = completed_sequence + 1

    %{
      old_kek_version: old_kek_version,
      new_kek_version: new_kek_version,
      started_event_hash: started_event.event_hash,
      completed_at_event_sequence: completed_sequence,
      deleted_at_event_sequence: deleted_sequence,
      server_rejects_old_key_uploads_after_sequence: deleted_sequence,
      completion_manifest_hash:
        rotation_completion_manifest_hash(
          workspace.id,
          old_kek_version,
          new_kek_version,
          started_event.event_hash
        ),
      deleted_secret_ids_hash:
        DeletionProofs.deleted_workspace_kek_secret_ids_hash(
          workspace.id,
          old_kek_version
        ),
      deleted_wrap_ids_hash: workspace_kek_records_hash(workspace.id, old_kek_version)
    }
  end

  def append_start!(workspace, events, checkpoint)
      when is_list(events) and is_map(checkpoint) do
    old_kek_version = workspace.current_kek_version
    new_kek_version = old_kek_version + 1

    case events do
      [%{"payload" => %{"event_type" => "rotation_started", "body" => started}}] ->
        :ok =
          assert_rotation_started_body!(
            started,
            workspace.id,
            old_kek_version,
            new_kek_version
          )

        Encryption.append_workspace_key_directory!(
          workspace.id,
          events,
          checkpoint,
          checkpoint_signer_kind: "device"
        )

      _ ->
        Repo.rollback(:invalid_key_directory)
    end
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  def append_start!(_, _, _), do: Repo.rollback(:invalid_key_directory)

  def append_completion!(
        workspace,
        new_kek_version,
        events,
        checkpoint,
        deletion_proofs,
        wipe_required_device_ids
      )
      when is_list(events) and is_map(checkpoint) do
    old_kek_version = workspace.current_kek_version

    case events do
      [
        %{"payload" => %{"event_type" => "rotation_completed", "body" => completed}} =
            completed_event,
        %{"payload" => %{"event_type" => "old_key_deleted", "body" => deleted}} = deleted_event
      ] ->
        started_event =
          latest_rotation_started_event!(
            workspace.id,
            old_kek_version,
            new_kek_version
          )

        rotation_completed_event_hash =
          key_directory_event_hash(completed_event["payload"])

        deletion_context =
          DeletionProofs.validate!(
            workspace.id,
            old_kek_version,
            rotation_completed_event_hash,
            deletion_proofs,
            wipe_required_device_ids
          )

        :ok =
          assert_rotation_completed_body!(
            completed,
            workspace.id,
            old_kek_version,
            new_kek_version,
            started_event.event_hash,
            completed_event["payload"]["sequence"]
          )

        :ok =
          assert_old_key_deleted_body!(
            deleted,
            workspace.id,
            old_kek_version,
            rotation_completed_event_hash,
            deletion_context,
            deleted_event["payload"]["sequence"]
          )

        Encryption.append_workspace_key_directory!(
          workspace.id,
          events,
          checkpoint,
          checkpoint_signer_kind: "device"
        )

        persist_rotation_deletion_evidence!(
          workspace.id,
          old_kek_version,
          key_directory_event_hash(deleted_event["payload"]),
          old_key_deletion_manifest(
            workspace.id,
            old_kek_version,
            rotation_completed_event_hash,
            deletion_context,
            deleted_event["payload"]["sequence"]
          ),
          deletion_proofs,
          wipe_required_device_ids
        )

      _ ->
        Repo.rollback(:invalid_key_directory)
    end
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  def append_completion!(_, _, _, _, _, _), do: Repo.rollback(:invalid_key_directory)

  defp key_directory_event_hash(payload),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(payload))

  defp assert_rotation_started_body!(body, workspace_id, old_kek_version, new_kek_version) do
    if body["event_type"] == "rotation_started" and
         body["rotation_kind"] == "kek" and
         body["scope_kind"] == "workspace" and
         body["scope_id"] == workspace_id and
         body["old_key_version"] == old_kek_version and
         body["new_key_version"] == new_kek_version do
      :ok
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp assert_rotation_completed_body!(
         body,
         workspace_id,
         old_kek_version,
         new_kek_version,
         started_event_hash,
         completed_event_sequence
       ) do
    expected_manifest_hash =
      rotation_completion_manifest_hash(
        workspace_id,
        old_kek_version,
        new_kek_version,
        started_event_hash
      )

    if body["event_type"] == "rotation_completed" and
         body["rotation_kind"] == "kek" and
         body["scope_kind"] == "workspace" and
         body["scope_id"] == workspace_id and
         body["old_key_version"] == old_kek_version and
         body["new_key_version"] == new_kek_version and
         body["completed_at_event_sequence"] == completed_event_sequence and
         body["completion_manifest_hash"] == expected_manifest_hash do
      :ok
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp assert_old_key_deleted_body!(
         body,
         workspace_id,
         old_kek_version,
         rotation_completed_event_hash,
         deletion_context,
         deleted_event_sequence
       ) do
    if body["deleted_at_event_sequence"] != deleted_event_sequence,
      do: Repo.rollback(:invalid_key_directory)

    expected_manifest_hash =
      old_key_deletion_manifest_hash(
        workspace_id,
        old_kek_version,
        rotation_completed_event_hash,
        deletion_context,
        deleted_event_sequence
      )

    if body["event_type"] == "old_key_deleted" and
         body["rotation_kind"] == "kek" and
         body["scope_kind"] == "workspace" and
         body["scope_id"] == workspace_id and
         body["old_key_version"] == old_kek_version and
         body["deletion_manifest_hash"] == expected_manifest_hash do
      :ok
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp rotation_completion_manifest_hash(
         workspace_id,
         old_kek_version,
         new_kek_version,
         started_event_hash
       ) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.rotation-completion-manifest",
        "version" => 1,
        "rotation_kind" => "kek",
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "old_key_version" => old_kek_version,
        "new_key_version" => new_kek_version,
        "started_event_hash" => started_event_hash,
        "active_recipient_devices_hash" => active_recipient_devices_hash(workspace_id),
        "member_envelope_records_hash" =>
          member_envelope_records_hash(workspace_id, new_kek_version),
        "new_key_records_hash" => workspace_kek_records_hash(workspace_id, new_kek_version),
        "old_key_records_hash" => workspace_kek_records_hash(workspace_id, old_kek_version),
        "semantic_state_proof_hash" =>
          rotation_completion_state_hash(workspace_id, old_kek_version, new_kek_version)
      })
    )
  end

  defp old_key_deletion_manifest_hash(
         workspace_id,
         old_kek_version,
         rotation_completed_event_hash,
         deletion_context,
         server_rejects_old_key_uploads_after_sequence
       ) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(
        old_key_deletion_manifest(
          workspace_id,
          old_kek_version,
          rotation_completed_event_hash,
          deletion_context,
          server_rejects_old_key_uploads_after_sequence
        )
      )
    )
  end

  defp old_key_deletion_manifest(
         workspace_id,
         old_kek_version,
         rotation_completed_event_hash,
         deletion_context,
         server_rejects_old_key_uploads_after_sequence
       ) do
    %{
      "protocol" => "refmd.old-key-deletion-manifest",
      "version" => 1,
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => workspace_id,
      "old_key_version" => old_kek_version,
      "rotation_completed_event_hash" => rotation_completed_event_hash,
      "deleted_secret_ids_hash" =>
        DeletionProofs.deleted_workspace_kek_secret_ids_hash(
          workspace_id,
          old_kek_version
        ),
      "deleted_wrap_ids_hash" => workspace_kek_records_hash(workspace_id, old_kek_version),
      "active_device_deletion_proofs_hash" => deletion_context.active_device_deletion_proofs_hash,
      "wipe_required_device_ids_hash" => deletion_context.wipe_required_device_ids_hash,
      "server_rejects_old_key_uploads_after_sequence" =>
        server_rejects_old_key_uploads_after_sequence
    }
  end

  defp persist_rotation_deletion_evidence!(
         workspace_id,
         old_kek_version,
         old_key_deleted_event_hash,
         deletion_manifest,
         deletion_proofs,
         wipe_required_device_ids
       ) do
    %WorkspaceKekRotationDeletionEvidence{}
    |> WorkspaceKekRotationDeletionEvidence.changeset(%{
      old_key_deleted_event_hash: old_key_deleted_event_hash,
      workspace_id: workspace_id,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: workspace_id,
      old_key_version: old_kek_version,
      deletion_manifest: deletion_manifest,
      device_key_deletion_proofs: %{"proofs" => deletion_proofs},
      wipe_required_device_ids: Enum.uniq(wipe_required_device_ids)
    })
    |> Repo.insert!()
  end

  defp latest_rotation_started_event!(workspace_id, old_kek_version, new_kek_version) do
    rotation_started_event(workspace_id, old_kek_version, new_kek_version)
    |> case do
      nil -> Repo.rollback(:invalid_key_directory)
      event -> event
    end
  end

  defp rotation_started_event(workspace_id, old_kek_version, new_kek_version) do
    Encryption.workspace_key_directory_events_up_to(
      workspace_id,
      current_workspace_event_sequence!(workspace_id)
    )
    |> Enum.reverse()
    |> Enum.find(fn event ->
      body = get_in(event.payload, ["body"])

      event.event_type == "rotation_started" and is_map(body) and
        body["rotation_kind"] == "kek" and body["scope_kind"] == "workspace" and
        body["scope_id"] == workspace_id and body["old_key_version"] == old_kek_version and
        body["new_key_version"] == new_kek_version
    end)
  end

  defp current_workspace_event_sequence!(workspace_id) do
    case Encryption.current_workspace_key_directory_pin(workspace_id) do
      %{event_head_sequence: sequence} when is_integer(sequence) and sequence > 0 -> sequence
      _ -> Repo.rollback(:invalid_key_directory)
    end
  end

  defp active_recipient_devices_hash(workspace_id) do
    records =
      active_workspace_device_ids(workspace_id)
      |> Enum.map(&%{"recipient_kind" => "workspace_device", "recipient_id" => &1})

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp member_envelope_records_hash(workspace_id, key_version) do
    records =
      from(e in RefMD.Encryption.WorkspaceMemberEnvelope,
        where: e.workspace_id == ^workspace_id and e.key_version == ^key_version,
        order_by: [asc: e.target_user_id],
        select: {e.target_user_id, e.wrap_body_hash}
      )
      |> Repo.all()
      |> Enum.map(fn {user_id, wrap_body_hash} ->
        %{
          "recipient_kind" => "workspace_member",
          "recipient_id" => user_id,
          "wrap_hash" => encode_hash(wrap_body_hash)
        }
      end)

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp workspace_kek_records_hash(workspace_id, key_version) do
    records =
      from(k in RefMD.Encryption.WorkspaceEncryptedKey,
        where: k.workspace_id == ^workspace_id and k.key_version == ^key_version,
        order_by: [asc: k.device_id],
        select: {k.device_id, k.wrap_body_hash}
      )
      |> Repo.all()
      |> Enum.map(fn {device_id, wrap_body_hash} ->
        %{
          "recipient_kind" => "workspace_device",
          "recipient_id" => device_id,
          "wrap_hash" => encode_hash(wrap_body_hash)
        }
      end)

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp rotation_completion_state_hash(workspace_id, old_kek_version, new_kek_version) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "workspace_id" => workspace_id,
        "old_kek_version" => old_kek_version,
        "new_kek_version" => new_kek_version,
        "active_device_ids" => active_workspace_device_ids(workspace_id)
      })
    )
  end

  defp active_workspace_device_ids(workspace_id) do
    DeletionProofs.active_workspace_device_ids(workspace_id)
  end

  defp encode_hash(value) when is_binary(value) and byte_size(value) == 32,
    do: Encoding.encode_base64url(value)

  defp encode_hash(value) when is_binary(value), do: value
end
