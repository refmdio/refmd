defmodule RefMD.Workspaces.KekRotation.DeletionProofs do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces.{WorkspaceGuestGrant, WorkspaceMember, WorkspaceRole}

  @protocol "refmd.device-key-deletion-proof"
  @storage_classes [
    "crypto_worker_state",
    "indexeddb_cache",
    "local_encrypted_key_store",
    "offline_cache",
    "pending_queue"
  ]

  @spec validate!(Ecto.UUID.t(), pos_integer(), binary(), [map()], [binary()]) :: %{
          active_device_deletion_proofs_hash: binary(),
          wipe_required_device_ids_hash: binary()
        }
  def validate!(
        workspace_id,
        old_kek_version,
        rotation_completed_event_hash,
        proofs,
        wipe_required_device_ids
      )
      when is_binary(workspace_id) and is_integer(old_kek_version) and old_kek_version > 0 and
             is_binary(rotation_completed_event_hash) and is_list(proofs) and
             is_list(wipe_required_device_ids) do
    Hash.assert_blake3_base64url!(rotation_completed_event_hash)

    active_devices =
      workspace_id
      |> active_workspace_devices()
      |> Map.new(&{&1.id, &1})

    wipe_required_ids = normalize_wipe_required_device_ids!(wipe_required_device_ids)
    assert_wipe_required_ids_supported!(wipe_required_ids, active_devices)

    checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace_id)
    deleted_secret_ids_hash = deleted_workspace_kek_secret_ids_hash(workspace_id, old_kek_version)

    proof_records =
      Enum.map(proofs, fn proof ->
        validate_proof!(
          proof,
          active_devices,
          workspace_id,
          old_kek_version,
          rotation_completed_event_hash,
          deleted_secret_ids_hash,
          checkpoint
        )
      end)

    proof_device_ids = proof_records |> Enum.map(& &1.device_id) |> MapSet.new()
    active_device_ids = active_devices |> Map.keys() |> MapSet.new()

    assert_deletion_proof_coverage!(
      proof_records,
      proof_device_ids,
      wipe_required_ids,
      active_device_ids
    )

    %{
      active_device_deletion_proofs_hash:
        active_device_deletion_proofs_hash(Enum.map(proof_records, & &1.proof_hash)),
      wipe_required_device_ids_hash:
        wipe_required_device_ids_hash(MapSet.to_list(wipe_required_ids))
    }
  end

  def validate!(_, _, _, _, _), do: raise(ArgumentError, "device_deletion_proofs_invalid")

  defp assert_wipe_required_ids_supported!(wipe_required_ids, active_devices) do
    active_device_ids = active_devices |> Map.keys() |> MapSet.new()

    unless MapSet.subset?(wipe_required_ids, active_device_ids),
      do: raise(ArgumentError, "wipe_required_device_unknown")
  end

  defp assert_deletion_proof_coverage!(
         proof_records,
         proof_device_ids,
         wipe_required_ids,
         active_device_ids
       ) do
    if MapSet.size(proof_device_ids) != length(proof_records),
      do: raise(ArgumentError, "duplicate_device_deletion_proof")

    unless MapSet.disjoint?(proof_device_ids, wipe_required_ids),
      do: raise(ArgumentError, "device_deletion_proof_wipe_overlap")

    unless MapSet.equal?(MapSet.union(proof_device_ids, wipe_required_ids), active_device_ids),
      do: raise(ArgumentError, "device_deletion_proof_coverage_incomplete")
  end

  @spec deleted_workspace_kek_secret_ids_hash(Ecto.UUID.t(), pos_integer()) :: binary()
  def deleted_workspace_kek_secret_ids_hash(workspace_id, old_kek_version) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "secret_ids" => ["workspace:kek:#{workspace_id}:#{old_kek_version}"]
      })
    )
  end

  @spec active_device_deletion_proofs_hash([binary()]) :: binary()
  def active_device_deletion_proofs_hash(proof_hashes) when is_list(proof_hashes) do
    sorted_unique_hashes =
      proof_hashes
      |> Enum.each(&Hash.assert_blake3_base64url!/1)
      |> then(fn _ -> proof_hashes end)
      |> Enum.uniq()
      |> Enum.sort()

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"proof_hashes" => sorted_unique_hashes}))
  end

  @spec wipe_required_device_ids_hash([binary()]) :: binary()
  def wipe_required_device_ids_hash(device_ids) when is_list(device_ids) do
    sorted_unique_ids =
      device_ids
      |> Enum.each(&assert_non_empty_string!/1)
      |> then(fn _ -> device_ids end)
      |> Enum.uniq()
      |> Enum.sort()

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"device_ids" => sorted_unique_ids}))
  end

  defp validate_proof!(
         proof,
         active_devices,
         workspace_id,
         old_kek_version,
         rotation_completed_event_hash,
         deleted_secret_ids_hash,
         checkpoint
       )
       when is_map(proof) do
    payload = fetch_map!(proof, "payload", "device_deletion_proof_payload_invalid")
    device_id = fetch_string!(payload, "device_id", "device_deletion_proof_device_invalid")

    device =
      Map.get(active_devices, device_id) ||
        raise(ArgumentError, "device_deletion_proof_signer_inactive")

    assert_checkpoint_active_signing_key!(checkpoint.payload, device)

    :ok =
      validate_payload!(
        payload,
        device_id,
        workspace_id,
        old_kek_version,
        rotation_completed_event_hash,
        deleted_secret_ids_hash
      )

    proof_hash = Hash.blake3_base64url(JCS.canonical_bytes!(payload))
    transcript = fetch_map!(proof, "transcript", "device_deletion_proof_transcript_invalid")
    signature = fetch_signature!(proof)

    proof_context = %{
      workspace_id: workspace_id,
      old_kek_version: old_kek_version,
      rotation_completed_event_hash: rotation_completed_event_hash,
      deleted_secret_ids_hash: deleted_secret_ids_hash
    }

    :ok =
      validate_transcript!(
        transcript,
        payload,
        device,
        proof_hash,
        checkpoint,
        proof_context
      )

    case Signature.verify_hybrid_signature_result(
           "device_key_deletion_proof",
           transcript,
           signature,
           device.public_material,
           key_deletion_semantic_context(device, proof_context)
         ) do
      :ok ->
        :ok

      {:error, :invalid_signature} ->
        raise(ArgumentError, "device_deletion_proof_signature_invalid")

      {:error, reason} ->
        raise(ArgumentError, Atom.to_string(reason))
    end

    %{device_id: device_id, proof_hash: proof_hash}
  end

  defp validate_proof!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "device_deletion_proof_invalid")

  defp key_deletion_semantic_context(device, context) do
    %{
      signer: %{
        id: device.id,
        signing_key_id: device.signing_key_id
      },
      deletion: %{
        scope_id: context.workspace_id,
        old_key_version: context.old_kek_version,
        rotation_completed_event_hash: context.rotation_completed_event_hash,
        deleted_secret_ids_hash: context.deleted_secret_ids_hash
      }
    }
  end

  defp validate_payload!(
         payload,
         device_id,
         workspace_id,
         old_kek_version,
         rotation_completed_event_hash,
         deleted_secret_ids_hash
       ) do
    expected_keys =
      Enum.sort([
        "deleted_secret_ids_hash",
        "deleted_storage_classes",
        "device_id",
        "local_cache_epoch",
        "old_key_version",
        "proof_nonce",
        "protocol",
        "rotation_completed_event_hash",
        "rotation_kind",
        "scope_id",
        "scope_kind",
        "version",
        "workspace_id"
      ])

    unless Enum.sort(Map.keys(payload)) == expected_keys,
      do: raise(ArgumentError, "device_deletion_proof_payload_keys_invalid")

    payload_checks = [
      payload["protocol"] == @protocol,
      payload["version"] == 1,
      payload["workspace_id"] == workspace_id,
      payload["device_id"] == device_id,
      payload["rotation_kind"] == "kek",
      payload["scope_kind"] == "workspace",
      payload["scope_id"] == workspace_id,
      payload["old_key_version"] == old_kek_version,
      payload["rotation_completed_event_hash"] == rotation_completed_event_hash,
      payload["deleted_secret_ids_hash"] == deleted_secret_ids_hash,
      deleted_storage_classes_valid?(payload["deleted_storage_classes"]),
      valid_cache_epoch?(payload["local_cache_epoch"]),
      valid_proof_nonce?(payload["proof_nonce"])
    ]

    if Enum.all?(payload_checks),
      do: :ok,
      else: raise(ArgumentError, "device_deletion_proof_payload_invalid")
  end

  defp validate_transcript!(
         transcript,
         payload,
         device,
         proof_hash,
         checkpoint,
         context
       ) do
    actor = fetch_map!(transcript, "actor", "device_deletion_proof_actor_invalid")

    authority =
      fetch_map!(transcript, "authority_boundary", "device_deletion_proof_authority_invalid")

    expected_deleted_storage_classes_hash =
      deleted_storage_classes_hash(payload["deleted_storage_classes"])

    valid? =
      transcript_subject_matches?(transcript, device, proof_hash) and
        transcript_actor_matches?(actor, device, checkpoint, context) and
        transcript_authority_matches?(authority, context, expected_deleted_storage_classes_hash)

    if valid?, do: :ok, else: raise(ArgumentError, "device_deletion_proof_transcript_invalid")
  end

  defp transcript_subject_matches?(transcript, device, proof_hash) do
    Enum.all?([
      transcript["owner_kind"] == "device",
      transcript["owner_id"] == device.id,
      transcript["signing_purpose"] == "device_key_deletion_proof",
      transcript["surface_variant"] == "device_key_deletion_proof",
      transcript["subject_protocol"] == @protocol,
      transcript["subject_version"] == 1,
      transcript["subject_hash"] == proof_hash
    ])
  end

  defp transcript_actor_matches?(actor, device, checkpoint, context) do
    Enum.all?([
      actor["signer_kind"] == "workspace_device",
      actor["user_id"] == device.user_id,
      actor["device_id"] == device.id,
      actor["signing_key_id"] == device.signing_key_id,
      actor["key_scope_kind"] == "workspace",
      actor["key_scope_id"] == context.workspace_id,
      actor["key_checkpoint_sequence"] == checkpoint.sequence,
      actor["key_checkpoint_hash"] == checkpoint.checkpoint_hash
    ])
  end

  defp transcript_authority_matches?(authority, context, expected_deleted_storage_classes_hash) do
    Enum.all?([
      authority["workspace_id"] == context.workspace_id,
      authority["rotation_kind"] == "kek",
      authority["scope_kind"] == "workspace",
      authority["scope_id"] == context.workspace_id,
      authority["old_key_version"] == context.old_kek_version,
      authority["rotation_completed_event_hash"] == context.rotation_completed_event_hash,
      authority["deleted_secret_ids_hash"] == context.deleted_secret_ids_hash,
      authority["deleted_storage_classes_hash"] == expected_deleted_storage_classes_hash
    ])
  end

  defp deleted_storage_classes_valid?(storage_classes) do
    is_list(storage_classes) and Enum.sort(storage_classes) == @storage_classes
  end

  defp valid_cache_epoch?(epoch), do: is_integer(epoch) and epoch >= 0

  defp active_workspace_devices(workspace_id) do
    from(m in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == m.role_id,
      left_join: g in WorkspaceGuestGrant,
      on:
        g.workspace_id == m.workspace_id and g.user_id == m.user_id and
          g.scope_kind == "workspace" and is_nil(g.revoked_at),
      join: d in RefMD.Devices.Device,
      on: d.user_id == m.user_id,
      where:
        m.workspace_id == ^workspace_id and (r.base_role != "guest" or not is_nil(g.user_id)) and
          is_nil(d.revoked_at),
      order_by: [asc: d.id],
      select: %{
        id: d.id,
        user_id: d.user_id,
        signing_key_id: d.signing_key_id,
        public_material: d.hybrid_signing_public_key_material
      }
    )
    |> Repo.all()
  end

  defp assert_checkpoint_active_signing_key!(checkpoint_payload, device) do
    entry =
      checkpoint_payload
      |> Map.get("device_keys", [])
      |> Enum.find(fn
        %{"key_id" => key_id, "key_material" => material} = entry ->
          key_id == device.signing_key_id and
            not Map.has_key?(entry, "revoked_at") and
            material == device.public_material and
            material["owner_kind"] == "device" and
            material["owner_id"] == device.id

        _ ->
          false
      end)

    if entry,
      do: :ok,
      else: raise(ArgumentError, "device_deletion_proof_signer_not_in_checkpoint")
  end

  defp normalize_wipe_required_device_ids!(device_ids) do
    Enum.map(device_ids, fn device_id ->
      assert_non_empty_string!(device_id)
      device_id
    end)
    |> MapSet.new()
  end

  defp fetch_signature!(%{"signature" => signature}) when is_map(signature), do: signature
  defp fetch_signature!(%{"hybrid_signature" => signature}) when is_map(signature), do: signature
  defp fetch_signature!(_), do: raise(ArgumentError, "device_deletion_proof_signature_missing")

  defp fetch_map!(map, key, error) when is_map(map) do
    case Map.get(map, key) do
      value when is_map(value) -> value
      _ -> raise(ArgumentError, error)
    end
  end

  defp fetch_string!(map, key, error) when is_map(map) do
    case Map.get(map, key) do
      value when is_binary(value) and byte_size(value) > 0 -> value
      _ -> raise(ArgumentError, error)
    end
  end

  defp deleted_storage_classes_hash(storage_classes) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{"storage_classes" => Enum.sort(storage_classes)})
    )
  end

  defp valid_proof_nonce?(value) when is_binary(value) do
    Encoding.decode_base64url!(value, 32)
    true
  rescue
    _ -> false
  end

  defp valid_proof_nonce?(_), do: false

  defp assert_non_empty_string!(value) when is_binary(value) and byte_size(value) > 0, do: :ok
  defp assert_non_empty_string!(_), do: raise(ArgumentError, "non_empty_string_invalid")
end
