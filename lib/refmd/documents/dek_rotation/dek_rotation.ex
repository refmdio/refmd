defmodule RefMD.Documents.DekRotation do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}

  alias RefMD.Documents.{
    Document,
    DocumentDekRotationDeletionEvidence,
    DocumentDeviceWipeRequirement,
    DocumentSnapshot,
    DocumentUpdate
  }

  alias RefMD.Encryption
  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces.KekRotation.DeletionProofs

  def completion_materials(document_id, new_key_version) do
    Repo.transaction(fn ->
      document = lock_document!(document_id)
      validate_rotation_snapshot!(document, new_key_version)
      old_key_version = new_key_version - 1
      started = started_event!(document, old_key_version, new_key_version)
      current_sequence = current_event_sequence!(document.workspace_id)

      %{
        old_key_version: old_key_version,
        new_key_version: new_key_version,
        started_event_hash: started.event_hash,
        completed_at_event_sequence: current_sequence + 1,
        deleted_at_event_sequence: current_sequence + 2,
        server_rejects_old_key_uploads_after_sequence: current_sequence + 2,
        completion_manifest_hash:
          completion_manifest_hash(document, old_key_version, new_key_version, started.event_hash),
        deleted_secret_ids_hash:
          DeletionProofs.deleted_document_dek_secret_ids_hash(document.id, old_key_version),
        deleted_wrap_ids_hash: deleted_wrap_ids_hash(document.id, old_key_version)
      }
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  def complete(
        document_id,
        new_key_version,
        events,
        checkpoint,
        deletion_proofs,
        wipe_required_device_ids
      )
      when is_list(events) and is_map(checkpoint) and is_list(deletion_proofs) and
             is_list(wipe_required_device_ids) do
    Repo.transaction(fn ->
      document = lock_document!(document_id)
      validate_rotation_snapshot!(document, new_key_version)
      old_key_version = new_key_version - 1
      started = started_event!(document, old_key_version, new_key_version)

      case events do
        [
          %{"payload" => %{"event_type" => "rotation_completed", "body" => completed}} =
              completed_event,
          %{"payload" => %{"event_type" => "old_key_deleted", "body" => deleted}} =
              deleted_event
        ] ->
          completed_hash = event_hash(completed_event)

          deletion_context =
            DeletionProofs.validate_dek!(
              document.workspace_id,
              document.id,
              old_key_version,
              completed_hash,
              deletion_proofs,
              wipe_required_device_ids
            )

          completion_manifest =
            assert_completion_body!(
              completed,
              document,
              old_key_version,
              new_key_version,
              started.event_hash,
              completed_event["payload"]["sequence"]
            )

          manifest =
            deletion_manifest(
              document,
              old_key_version,
              completed_hash,
              deletion_context,
              deleted_event["payload"]["sequence"]
            )

          assert_deletion_body!(
            deleted,
            document,
            old_key_version,
            manifest,
            deleted_event["payload"]["sequence"]
          )

          Encryption.append_workspace_key_directory!(
            document.workspace_id,
            events,
            checkpoint,
            checkpoint_signer_kind: "device"
          )

          delete_obsolete_records!(document.id, new_key_version)

          persist_evidence!(
            document,
            old_key_version,
            deleted_event,
            completion_manifest,
            manifest,
            deletion_proofs,
            wipe_required_device_ids
          )

          persist_wipe_requirements!(document.id, new_key_version, wipe_required_device_ids)

          from(d in Document, where: d.id == ^document.id)
          |> Repo.update_all(set: [needs_rotation_snapshot: false])

          :ok

        _ ->
          Repo.rollback(:invalid_key_directory)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def complete(_, _, _, _, _, _), do: {:error, :invalid_key_directory}

  def wipe_required?(document_id, device_id) do
    from(r in DocumentDeviceWipeRequirement,
      where: r.document_id == ^document_id and r.device_id == ^device_id
    )
    |> Repo.exists?()
  end

  def deletion_evidences_by_event_hash(event_hashes) when is_list(event_hashes) do
    from(e in DocumentDekRotationDeletionEvidence,
      where: e.old_key_deleted_event_hash in ^event_hashes
    )
    |> Repo.all()
    |> Map.new(&{&1.old_key_deleted_event_hash, &1})
  end

  def wipe_requirement(document_id, device_id) do
    with %DocumentDeviceWipeRequirement{} = requirement <-
           oldest_wipe_requirement(document_id, device_id),
         %DocumentDekRotationDeletionEvidence{} = evidence <-
           wipe_evidence(document_id, device_id, requirement.required_dek_version) do
      {:ok,
       %{
         workspace_id: evidence.workspace_id,
         required_dek_version: requirement.required_dek_version,
         old_key_version: evidence.old_key_version,
         rotation_completed_event_hash:
           evidence.deletion_manifest["rotation_completed_event_hash"],
         deleted_secret_ids_hash: evidence.deletion_manifest["deleted_secret_ids_hash"]
       }}
    else
      _ -> {:error, :wipe_requirement_not_found}
    end
  end

  def acknowledge_wipe(document_id, device_id, proof) when is_map(proof) do
    Repo.transaction(fn ->
      requirement =
        from(r in DocumentDeviceWipeRequirement,
          where: r.document_id == ^document_id and r.device_id == ^device_id,
          order_by: [asc: r.required_dek_version],
          limit: 1,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      if is_nil(requirement), do: Repo.rollback(:wipe_requirement_not_found)

      evidence =
        wipe_evidence(document_id, device_id, requirement.required_dek_version) ||
          Repo.rollback(:wipe_requirement_not_found)

      :ok =
        DeletionProofs.validate_dek_ack!(
          evidence.workspace_id,
          document_id,
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

  defp lock_document!(document_id) do
    from(d in Document, where: d.id == ^document_id, lock: "FOR UPDATE")
    |> Repo.one()
    |> case do
      nil -> Repo.rollback(:document_not_found)
      document -> document
    end
  end

  defp wipe_evidence(document_id, device_id, required_dek_version) do
    from(e in DocumentDekRotationDeletionEvidence,
      where: e.document_id == ^document_id and e.old_key_version == ^(required_dek_version - 1),
      order_by: [desc: e.inserted_at]
    )
    |> Repo.all()
    |> Enum.find(&(device_id in &1.wipe_required_device_ids))
  end

  defp validate_rotation_snapshot!(document, new_key_version) do
    snapshot =
      document.active_snapshot_id && Repo.get(DocumentSnapshot, document.active_snapshot_id)

    key =
      Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: new_key_version)

    title_reencrypted =
      is_nil(document.encrypted_title) or document.encrypted_title_key_version == new_key_version

    unless valid_rotation_snapshot?(document, snapshot, key, new_key_version, title_reencrypted) do
      Repo.rollback(:rotation_snapshot_required)
    end
  end

  defp valid_rotation_snapshot?(document, snapshot, key, new_key_version, title_reencrypted) do
    document.needs_rotation_snapshot and
      new_key_version == document.min_dek_version and
      new_key_version > 1 and
      not is_nil(snapshot) and
      snapshot.key_version == new_key_version and
      not is_nil(key) and
      title_reencrypted
  end

  defp started_event!(document, old_key_version, new_key_version) do
    Encryption.workspace_key_directory_events_up_to(
      document.workspace_id,
      current_event_sequence!(document.workspace_id)
    )
    |> Enum.reverse()
    |> Enum.find(fn event ->
      body = event.payload["body"]

      event.event_type == "rotation_started" and is_map(body) and
        body["rotation_kind"] == "dek" and body["scope_kind"] == "document" and
        body["scope_id"] == document.id and body["old_key_version"] == old_key_version and
        body["new_key_version"] == new_key_version
    end)
    |> case do
      nil -> Repo.rollback(:invalid_key_directory)
      event -> event
    end
  end

  defp current_event_sequence!(workspace_id) do
    case Encryption.current_workspace_key_directory_pin(workspace_id) do
      %{event_head_sequence: sequence} when is_integer(sequence) and sequence > 0 -> sequence
      _ -> Repo.rollback(:invalid_key_directory)
    end
  end

  defp completion_manifest(document, old_version, new_version, started_hash) do
    snapshot = Repo.get!(DocumentSnapshot, document.active_snapshot_id)

    new_key =
      Repo.get_by!(DocumentEncryptedKey, document_id: document.id, key_version: new_version)

    old_updates =
      from(u in DocumentUpdate,
        where: u.document_id == ^document.id and u.key_version == ^old_version,
        select: {u.clock, u.update_hash}
      )
      |> Repo.all()

    old_update_hashes = old_updates |> Enum.map(&elem(&1, 1)) |> Enum.sort()
    clocks = Enum.map(old_updates, &elem(&1, 0))

    %{
      "protocol" => "refmd.rotation-completion-manifest",
      "version" => 1,
      "rotation_kind" => "dek",
      "scope_kind" => "document",
      "scope_id" => document.id,
      "old_key_version" => old_version,
      "new_key_version" => new_version,
      "started_event_hash" => started_hash,
      "new_key_records" =>
        document.workspace_id
        |> DeletionProofs.active_workspace_device_ids()
        |> Enum.map(fn device_id ->
          %{
            "recipient_kind" => "workspace_device",
            "recipient_id" => device_id,
            "wrap_id" => "document:dek:#{document.id}:#{new_version}:device:#{device_id}",
            "key_version" => new_version,
            "wrap_hash" =>
              Hash.blake3_base64url(
                JCS.canonical_bytes!(%{
                  "encrypted_dek" => Base.url_encode64(new_key.encrypted_dek, padding: false),
                  "nonce" => Base.url_encode64(new_key.nonce, padding: false),
                  "kek_version" => new_key.kek_version,
                  "recipient_device_id" => device_id
                })
              )
          }
        end),
      "rewritten_records" => %{
        "snapshot_id" => snapshot.id,
        "ciphertext_hash" => snapshot.ciphertext_hash,
        "covered_update_start_clock" => min_clock(clocks),
        "covered_update_end_clock" => max_clock(clocks),
        "old_dek_update_hashes_hash" => hashes_hash(old_update_hashes),
        "new_dek_update_hashes_hash" => hashes_hash([])
      },
      "deleted_wrap_ids_hash" => deleted_wrap_ids_hash(document.id, old_version),
      "semantic_state_proof_hash" => snapshot.proof_chain_hash
    }
  end

  defp completion_manifest_hash(document, old_version, new_version, started_hash) do
    document
    |> completion_manifest(old_version, new_version, started_hash)
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  defp min_clock([]), do: 0
  defp min_clock(clocks), do: Enum.min(clocks)
  defp max_clock([]), do: 0
  defp max_clock(clocks), do: Enum.max(clocks)

  defp hashes_hash(hashes),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(%{"hashes" => Enum.sort(hashes)}))

  defp deleted_wrap_ids_hash(document_id, old_version) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "wrap_ids" => ["document:dek:#{document_id}:#{old_version}"]
      })
    )
  end

  defp assert_completion_body!(body, document, old_version, new_version, started_hash, sequence) do
    manifest = completion_manifest(document, old_version, new_version, started_hash)
    expected_hash = Hash.blake3_base64url(JCS.canonical_bytes!(manifest))

    unless body == %{
             "event_type" => "rotation_completed",
             "rotation_kind" => "dek",
             "scope_kind" => "document",
             "scope_id" => document.id,
             "old_key_version" => old_version,
             "new_key_version" => new_version,
             "completed_at_event_sequence" => sequence,
             "completion_manifest_hash" => expected_hash
           },
           do: Repo.rollback(:invalid_key_directory)

    manifest
  end

  defp assert_deletion_body!(body, document, old_version, manifest, sequence) do
    expected = %{
      "event_type" => "old_key_deleted",
      "rotation_kind" => "dek",
      "scope_kind" => "document",
      "scope_id" => document.id,
      "old_key_version" => old_version,
      "deleted_at_event_sequence" => sequence,
      "deletion_manifest_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(manifest))
    }

    unless body == expected, do: Repo.rollback(:invalid_key_directory)
  end

  defp deletion_manifest(document, old_version, completed_hash, context, sequence) do
    %{
      "protocol" => "refmd.old-key-deletion-manifest",
      "version" => 1,
      "rotation_kind" => "dek",
      "scope_kind" => "document",
      "scope_id" => document.id,
      "old_key_version" => old_version,
      "rotation_completed_event_hash" => completed_hash,
      "deleted_secret_ids_hash" =>
        DeletionProofs.deleted_document_dek_secret_ids_hash(document.id, old_version),
      "deleted_wrap_ids_hash" => deleted_wrap_ids_hash(document.id, old_version),
      "active_device_deletion_proofs_hash" => context.active_device_deletion_proofs_hash,
      "wipe_required_device_ids_hash" => context.wipe_required_device_ids_hash,
      "server_rejects_old_key_uploads_after_sequence" => sequence
    }
  end

  defp delete_obsolete_records!(document_id, new_version) do
    from(u in DocumentUpdate,
      where: u.document_id == ^document_id and u.key_version < ^new_version
    )
    |> Repo.delete_all()

    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.key_version < ^new_version
    )
    |> Repo.delete_all()

    Sharing.delete_obsolete_share_key_wraps!(document_id, new_version)
  end

  defp persist_evidence!(
         document,
         old_version,
         deleted_event,
         completion_manifest,
         deletion_manifest,
         proofs,
         wipe_ids
       ) do
    %DocumentDekRotationDeletionEvidence{}
    |> DocumentDekRotationDeletionEvidence.changeset(%{
      old_key_deleted_event_hash: event_hash(deleted_event),
      document_id: document.id,
      workspace_id: document.workspace_id,
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: document.id,
      old_key_version: old_version,
      completion_manifest: completion_manifest,
      deletion_manifest: deletion_manifest,
      device_key_deletion_proofs: %{"proofs" => proofs},
      wipe_required_device_ids: Enum.uniq(wipe_ids)
    })
    |> Repo.insert!()
  end

  defp persist_wipe_requirements!(_document_id, _new_version, []), do: :ok

  defp persist_wipe_requirements!(document_id, new_version, device_ids) do
    now = DateTime.utc_now()

    rows =
      device_ids
      |> Enum.uniq()
      |> Enum.map(
        &%{
          document_id: document_id,
          device_id: &1,
          required_dek_version: new_version,
          reason: "dek_rotation_deletion_proof_missing",
          required_at: now,
          inserted_at: now
        }
      )

    Repo.insert_all(DocumentDeviceWipeRequirement, rows,
      on_conflict: :nothing,
      conflict_target: [:document_id, :device_id, :required_dek_version]
    )
  end

  defp oldest_wipe_requirement(document_id, device_id) do
    from(r in DocumentDeviceWipeRequirement,
      where: r.document_id == ^document_id and r.device_id == ^device_id,
      order_by: [asc: r.required_dek_version],
      limit: 1
    )
    |> Repo.one()
  end

  defp event_hash(%{"payload" => payload}),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(payload))
end
