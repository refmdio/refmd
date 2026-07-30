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

  def completion_manifest_hash(workspace, command, prepared) do
    started_event =
      rotation_started_event(
        workspace.id,
        command["old_key_version"],
        command["new_key_version"]
      ) || raise(ArgumentError, "kek_rotation_started_event_missing")

    device_records =
      Enum.map(prepared.device_wraps, fn entry ->
        %{
          "recipient_kind" => "workspace_device",
          "recipient_id" => entry.target_device_id,
          "wrap_hash" => entry.wrap_body_hash
        }
      end)

    member_records =
      Enum.map(prepared.member_envelopes, fn entry ->
        %{
          "recipient_kind" => "workspace_member",
          "recipient_id" => entry.precommit["target_user_id"],
          "wrap_hash" => entry.wrap_body_hash
        }
      end)

    manifest = %{
      "protocol" => "refmd.rotation-completion-manifest",
      "version" => 1,
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => workspace.id,
      "old_key_version" => command["old_key_version"],
      "new_key_version" => command["new_key_version"],
      "started_event_hash" => started_event.event_hash,
      "active_recipient_devices_hash" => records_hash(device_records),
      "member_envelope_records_hash" => records_hash(member_records),
      "new_key_records_hash" => records_hash(device_records),
      "old_key_records_hash" =>
        workspace_kek_records_hash(workspace.id, command["old_key_version"]),
      "workspace_invitation_updates_hash" =>
        records_hash(command["workspace_invitation_updates"]),
      "guest_invitation_updates_hash" => records_hash(command["guest_invitation_updates"]),
      "semantic_state_proof_hash" =>
        records_hash(%{
          "workspace_id" => workspace.id,
          "device_records" => device_records,
          "member_records" => member_records,
          "workspace_invitation_ids" =>
            Enum.map(command["workspace_invitation_updates"], & &1["invitation_id"]),
          "guest_invitation_ids" =>
            Enum.map(command["guest_invitation_updates"], & &1["guest_invitation_id"])
        })
    }

    Hash.blake3_base64url(JCS.canonical_bytes!(manifest))
  end

  def old_key_deletion_material(workspace_id, old_kek_version) do
    %{
      "deleted_secret_ids_hash" =>
        DeletionProofs.deleted_workspace_kek_secret_ids_hash(workspace_id, old_kek_version),
      "deleted_wrap_ids_hash" => workspace_kek_records_hash(workspace_id, old_kek_version)
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

  def validate_old_key_deletion_manifest!(workspace, manifest, deletion_context)
      when is_map(manifest) do
    expected =
      old_key_deletion_manifest(
        workspace.id,
        workspace.min_kek_version,
        workspace.kek_rotation_completed_event_hash,
        deletion_context,
        manifest["server_rejects_old_key_uploads_after_sequence"]
      )

    if manifest == expected,
      do: :ok,
      else: raise(ArgumentError, "kek_rotation_deletion_manifest_invalid")
  end

  def persist_old_key_deletion_evidence!(
        workspace,
        old_key_deleted_event_hash,
        deletion_manifest,
        deletion_proofs,
        wipe_required_device_ids
      ) do
    persist_rotation_deletion_evidence!(
      workspace.id,
      workspace.min_kek_version,
      old_key_deleted_event_hash,
      deletion_manifest,
      deletion_proofs,
      wipe_required_device_ids
    )
  end

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

  defp records_hash(records),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))

  defp encode_hash(value) when is_binary(value) and byte_size(value) == 32,
    do: Encoding.encode_base64url(value)

  defp encode_hash(value) when is_binary(value), do: value
end
