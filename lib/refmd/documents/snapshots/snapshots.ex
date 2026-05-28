defmodule RefMD.Documents.Snapshots do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Blake3, Encoding, Hash, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Documents.{Admission, Document, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Documents.Snapshots.{ProofChain, SignerKeys}
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces

  # Clocks are snapshot-scoped: each new snapshot starts with no accumulated
  # per-device clocks. Pre-snapshot clocks are captured in parent_snapshot_update_clocks.
  # update_snapshot_metadata populates this field as updates arrive.
  @initial_snapshot_clocks %{}

  @spec build_snapshot_proof_chain(Ecto.UUID.t(), Ecto.UUID.t() | nil, Ecto.UUID.t() | nil) ::
          [map()]
  defdelegate build_snapshot_proof_chain(document_id, pinned_snapshot_id, active_snapshot_id),
    to: ProofChain

  # ── Save Update ─────────────────────────────────

  @spec save_update(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def save_update(document_id, actor_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_writable!(document)
      validate_write_permission!(document, actor_id, attrs)
      validate_device_active!(actor_id, attrs)
      verify_document_operation_signature_once!("document_update", actor_id, attrs, document)
      validate_update_preconditions!(document, attrs)

      case get_existing_by_hash(document_id, attrs.update_hash) do
        %DocumentUpdate{} = existing ->
          duplicate_update_result(existing)

        nil ->
          insert_new_update(document, document_id, actor_id, attrs)
      end
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  defp insert_new_update(document, document_id, actor_id, attrs) do
    admission_event_hash = Admission.append_update!(document, attrs)
    attrs = Map.put(attrs, :admission_event_hash, admission_event_hash)

    case insert_update_atomic(document_id, attrs.ref_snapshot_id, attrs) do
      %{duplicate: true} = result ->
        result

      result ->
        SignerKeys.record_document_signer!(document_id, actor_id, attrs)
        result
    end
  end

  defp duplicate_update_result(existing) do
    %{
      snapshot_id: existing.snapshot_id,
      clock: existing.clock,
      update_hash: existing.update_hash,
      version: existing.version,
      duplicate: true
    }
  end

  defp validate_update_preconditions!(document, attrs) do
    cond do
      is_nil(document.active_snapshot_id) ->
        Repo.rollback(:snapshot_mismatch)

      document.active_snapshot_id != attrs.ref_snapshot_id ->
        Repo.rollback(:snapshot_mismatch)

      attrs.key_version < document.min_dek_version ->
        Repo.rollback(:key_version_too_old)

      document.needs_dek_rotation ->
        Repo.rollback(:key_rotation_required)

      document.needs_rotation_snapshot ->
        Repo.rollback(:rotation_snapshot_required)

      true ->
        :ok
    end
  end

  # ── Save Snapshot ──────────────────────────────

  @spec save_snapshot(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom(), map() | nil}
  def save_snapshot(document_id, actor_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_writable!(document)
      validate_write_permission!(document, actor_id, attrs)
      validate_device_active!(actor_id, attrs)
      verify_document_operation_signature_once!("document_snapshot", actor_id, attrs, document)

      latest_version = validate_snapshot_preconditions!(document, attrs)

      snapshot_id = attrs.snapshot_id

      Admission.append_snapshot!(document, attrs)
      snapshot = insert_snapshot!(document_id, snapshot_id, latest_version, attrs)
      SignerKeys.record_document_signer!(document_id, actor_id, attrs)

      cas_result =
        cas_update_active_snapshot(document_id, snapshot_id, attrs.parent_snapshot_id)

      if cas_result == 0 do
        Repo.rollback({:parent_mismatch, build_recovery_data(document)})
      end

      maybe_clear_rotation_snapshot(document, document_id, attrs.key_version)

      %{
        snapshot_id: snapshot_id,
        latest_version: latest_version,
        proof_chain_hash: snapshot.proof_chain_hash,
        ciphertext_hash: snapshot.ciphertext_hash,
        snapshot_admission_event_hash: snapshot.snapshot_admission_event_hash
      }
    end)
    |> case do
      {:ok, result} ->
        {:ok, result}

      {:error, {reason, recovery}} ->
        {:error, reason, recovery}

      {:error, :serialization_conflict} ->
        {:error, :serialization_conflict, build_recovery_data_outside_tx(document_id)}

      {:error, reason} ->
        {:error, reason, nil}
    end
  end

  # ── Save Transaction Helpers ────────────────────

  @insert_update_sql """
  INSERT INTO document_updates (
    document_id, snapshot_id, clock, version,
    signing_key_id, update_data, nonce, key_version,
    update_hash, hybrid_signature, owner_kind, owner_id,
    authority_kind, authority_id, authority_context_key, authority_scope_id,
    authority_permission_version, key_checkpoint_sequence, key_checkpoint_hash,
    admission_event_hash, write_session_counter, timestamp, created_at
  )
  SELECT $1, $2, $3,
    COALESCE((SELECT MAX(version) FROM document_updates WHERE document_id = $1), 0) + 1,
    $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW()
  WHERE $3 = COALESCE(
    (
      SELECT MAX(clock) + 1
      FROM document_updates
      WHERE snapshot_id = $2 AND authority_context_key = $14 AND signing_key_id = $4
    ), 0
  )
  ON CONFLICT (document_id, update_hash) DO NOTHING
  RETURNING version
  """

  defp insert_update_atomic(document_id, ref_snapshot_id, attrs) do
    result =
      Repo.query!(
        @insert_update_sql,
        [
          Ecto.UUID.dump!(document_id),
          Ecto.UUID.dump!(ref_snapshot_id),
          attrs.clock,
          attrs.signing_key_id,
          attrs.update_data,
          attrs.nonce,
          attrs.key_version,
          attrs.update_hash,
          attrs.hybrid_signature,
          attrs.owner_kind,
          attrs.owner_id,
          attrs.authority_kind,
          attrs.authority_id,
          attrs.authority_context_key,
          attrs.authority_scope_id,
          attrs.authority_permission_version,
          attrs.key_checkpoint_sequence,
          attrs.key_checkpoint_hash,
          attrs.admission_event_hash,
          attrs.write_session_counter,
          attrs.timestamp
        ]
      )

    case result.rows do
      [[version]] ->
        update_snapshot_metadata(
          ref_snapshot_id,
          attrs.authority_context_key,
          attrs.signing_key_id,
          attrs.clock,
          version
        )

        %{
          snapshot_id: ref_snapshot_id,
          clock: attrs.clock,
          update_hash: attrs.update_hash,
          version: version
        }

      [] ->
        case get_existing_by_hash(document_id, attrs.update_hash) do
          nil ->
            Repo.rollback(:clock_mismatch)

          existing ->
            %{
              snapshot_id: existing.snapshot_id,
              clock: existing.clock,
              update_hash: existing.update_hash,
              version: existing.version,
              duplicate: true
            }
        end
    end
  end

  defp validate_snapshot_preconditions!(document, attrs) do
    validate_parent_snapshot!(document, attrs)
    current_snapshot = load_current_snapshot(document)
    validate_clocks!(document, attrs, current_snapshot)
    validate_snapshot_key_version!(document, attrs)
    if current_snapshot, do: current_snapshot.latest_version, else: 0
  end

  defp validate_parent_snapshot!(document, attrs) do
    parent_snapshot_id = attrs.parent_snapshot_id
    genesis = is_nil(parent_snapshot_id) and is_nil(document.active_snapshot_id)
    parent_match = document.active_snapshot_id == parent_snapshot_id

    unless genesis or parent_match do
      Repo.rollback({:parent_mismatch, build_recovery_data(document)})
    end

    if genesis do
      if attrs.parent_proof_hash != "GENESIS" or attrs.parent_snapshot_update_clocks != %{} do
        Repo.rollback({:invalid_genesis, nil})
      end
    else
      verify_parent_proof_hash!(document, attrs)
    end
  end

  defp verify_parent_proof_hash!(document, attrs) do
    parent = Repo.get(DocumentSnapshot, document.active_snapshot_id)

    if is_nil(parent) do
      Repo.rollback({:parent_mismatch, build_recovery_data(document)})
    end

    expected_proof = ProofChain.compute_snapshot_proof_link_hash(parent)

    unless attrs.parent_proof_hash == expected_proof do
      Repo.rollback({:parent_mismatch, build_recovery_data(document)})
    end
  end

  defp load_current_snapshot(document) do
    if document.active_snapshot_id,
      do: Repo.get(DocumentSnapshot, document.active_snapshot_id)
  end

  defp validate_clocks!(document, attrs, current_snapshot) do
    current_clocks = if current_snapshot, do: current_snapshot.clocks, else: %{}

    unless attrs.parent_snapshot_update_clocks == current_clocks do
      Repo.rollback({:clocks_mismatch, build_recovery_data(document)})
    end
  end

  defp validate_snapshot_key_version!(document, attrs) do
    cond do
      attrs.key_version < document.min_dek_version ->
        Repo.rollback({:key_version_too_old, build_recovery_data(document)})

      document.needs_dek_rotation ->
        Repo.rollback({:key_version_too_old, build_recovery_data(document)})

      true ->
        :ok
    end
  end

  defp maybe_clear_rotation_snapshot(document, document_id, key_version) do
    if document.needs_rotation_snapshot and key_version >= document.min_dek_version do
      dek_exists =
        Repo.exists?(
          from(k in RefMD.Encryption.DocumentEncryptedKey,
            where: k.document_id == ^document_id and k.key_version == ^key_version
          )
        )

      if dek_exists do
        delete_obsolete_document_keys(document_id, key_version)

        from(d in Document, where: d.id == ^document_id)
        |> Repo.update_all(set: [needs_rotation_snapshot: false])
      end
    end
  end

  defp delete_obsolete_document_keys(document_id, key_version) do
    from(k in RefMD.Encryption.DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.key_version < ^key_version
    )
    |> Repo.delete_all()
  end

  defp insert_snapshot!(document_id, snapshot_id, latest_version, attrs) do
    ciphertext_hash = Blake3.hash_base64url(attrs.data)
    snapshot_signature_hash = Blake3.hash_base64url(JCS.canonical_bytes!(attrs.hybrid_signature))
    snapshot_admission_event_hash = snapshot_admission_event_hash!(attrs)

    proof_chain_hash =
      ProofChain.compute_snapshot_proof_link_hash(%{
        document_id: document_id,
        id: snapshot_id,
        parent_snapshot_id: attrs.parent_snapshot_id,
        parent_proof_hash: attrs.parent_proof_hash,
        ciphertext_hash: ciphertext_hash,
        snapshot_signature_hash: snapshot_signature_hash,
        snapshot_admission_event_hash: snapshot_admission_event_hash
      })

    changeset =
      DocumentSnapshot.changeset(%DocumentSnapshot{}, %{
        id: snapshot_id,
        document_id: document_id,
        parent_snapshot_id: attrs.parent_snapshot_id,
        latest_version: latest_version,
        data: attrs.data,
        nonce: attrs.nonce,
        key_version: attrs.key_version,
        hybrid_signature: attrs.hybrid_signature,
        ciphertext_hash: ciphertext_hash,
        snapshot_signature_hash: snapshot_signature_hash,
        snapshot_admission_event_hash: snapshot_admission_event_hash,
        proof_chain_hash: proof_chain_hash,
        clocks: @initial_snapshot_clocks,
        parent_snapshot_update_clocks: attrs.parent_snapshot_update_clocks,
        parent_proof_hash: attrs.parent_proof_hash,
        created_by_signing_key_id: attrs.created_by_signing_key_id,
        owner_kind: attrs.owner_kind,
        owner_id: attrs.owner_id,
        authority_kind: attrs.authority_kind,
        authority_id: attrs.authority_id,
        authority_context_key: attrs.authority_context_key,
        authority_scope_id: attrs.authority_scope_id,
        authority_permission_version: attrs.authority_permission_version,
        key_checkpoint_sequence: attrs.key_checkpoint_sequence,
        key_checkpoint_hash: attrs.key_checkpoint_hash
      })

    case Repo.insert(changeset) do
      {:ok, snapshot} ->
        snapshot

      {:error, _changeset} ->
        Repo.rollback({:insert_failed, nil})
    end
  end

  defp snapshot_admission_event_hash!(%{admission: %{"workspaceKeyDirectoryEvents" => events}})
       when is_list(events) do
    events
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => "document_snapshot_accepted"} = payload} ->
        Blake3.hash_base64url(JCS.canonical_bytes!(payload))

      _ ->
        nil
    end)
    |> case do
      nil -> raise ArgumentError, "snapshot_admission_event_missing"
      event_hash -> event_hash
    end
  end

  # ── Save Helpers ───────────────────────────────

  defp lock_document(document_id) do
    case Repo.query(
           "SELECT id, workspace_id, active_snapshot_id, archived_at, write_state, min_dek_version, needs_dek_rotation, needs_rotation_snapshot FROM documents WHERE id = $1 FOR UPDATE",
           [Ecto.UUID.dump!(document_id)]
         ) do
      {:ok, %{rows: [row]}} ->
        [
          id,
          workspace_id,
          active_snapshot_id,
          archived_at,
          write_state,
          min_dek_version,
          needs_dek_rotation,
          needs_rotation_snapshot
        ] =
          row

        %{
          id: Ecto.UUID.load!(id),
          workspace_id: Ecto.UUID.load!(workspace_id),
          active_snapshot_id: if(active_snapshot_id, do: Ecto.UUID.load!(active_snapshot_id)),
          archived_at: archived_at,
          write_state: write_state || "writable",
          min_dek_version: min_dek_version,
          needs_dek_rotation: needs_dek_rotation,
          needs_rotation_snapshot: needs_rotation_snapshot
        }

      _ ->
        Repo.rollback(:document_not_found)
    end
  end

  defp validate_writable!(%{archived_at: archived_at}) when not is_nil(archived_at),
    do: Repo.rollback(:document_archived)

  defp validate_writable!(%{write_state: "writable"}), do: :ok
  defp validate_writable!(%{write_state: "read_only"}), do: Repo.rollback(:document_read_only)
  defp validate_writable!(%{write_state: "archived"}), do: Repo.rollback(:document_archived)

  defp validate_writable!(%{write_state: "write_disabled"}),
    do: Repo.rollback(:document_write_disabled)

  defp validate_writable!(_document), do: :ok

  defp validate_device_active!(_actor_id, %{session_kind: :share_participant} = attrs) do
    principal_id = Map.fetch!(attrs, :principal_id)
    validate_share_device_active!(principal_id, owner_id!(attrs))
  end

  defp validate_device_active!(_actor_id, attrs) do
    validate_member_device_not_revoked!(owner_id!(attrs))
  end

  defp validate_member_device_not_revoked!(device_id) do
    result =
      Repo.query(
        "SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NULL FOR SHARE",
        [Ecto.UUID.dump!(device_id)]
      )

    case result do
      {:ok, %{num_rows: 1}} -> :ok
      _ -> Repo.rollback(:device_revoked)
    end
  end

  defp validate_share_device_active!(principal_id, device_id) do
    case Sharing.lock_participant_device_active(principal_id, device_id) do
      :ok -> :ok
      {:error, _reason} -> Repo.rollback(:device_revoked)
    end
  end

  defp verify_document_operation_signature_once!(
         _purpose,
         _actor_id,
         %{signature_verified: true},
         _document
       ),
       do: :ok

  defp verify_document_operation_signature_once!(purpose, actor_id, attrs, document) do
    public_material = document_operation_public_material!(attrs)
    ciphertext = Encoding.encode_base64url(document_operation_ciphertext!(purpose, attrs))
    nonce = Encoding.encode_base64url(Map.fetch!(attrs, :nonce))

    transcript =
      case purpose do
        "document_update" ->
          Signature.build_document_update_transcript!(%{
            owner_kind: Map.fetch!(attrs, :owner_kind),
            owner_id: Map.fetch!(attrs, :owner_id),
            workspace_id: Map.fetch!(attrs, :workspace_id),
            actor_user_id: document_operation_actor_user_id!(attrs, actor_id),
            actor_device_id: owner_id!(attrs),
            signing_key_id: Map.fetch!(attrs, :signing_key_id),
            public_data: Map.fetch!(attrs, :public_data),
            authority_boundary: authority_boundary!(attrs, "document_write_session_admitted"),
            ciphertext: ciphertext,
            nonce: nonce
          })

        "document_snapshot" ->
          Signature.build_document_snapshot_transcript!(%{
            owner_kind: Map.fetch!(attrs, :owner_kind),
            owner_id: Map.fetch!(attrs, :owner_id),
            workspace_id: Map.fetch!(attrs, :workspace_id),
            actor_user_id: document_operation_actor_user_id!(attrs, actor_id),
            actor_device_id: owner_id!(attrs),
            signing_key_id: Map.fetch!(attrs, :created_by_signing_key_id),
            public_data: Map.fetch!(attrs, :public_data),
            authority_boundary: authority_boundary!(attrs, "document_snapshot_accepted"),
            ciphertext: ciphertext,
            nonce: nonce
          })
      end

    case Signature.verify_hybrid_signature_result(
           purpose,
           transcript,
           Map.fetch!(attrs, :hybrid_signature),
           public_material,
           %{
             document: %{
               id: document.id,
               workspace_id: document.workspace_id
             },
             session: %{
               kind: Map.get(attrs, :session_kind),
               user_id: document_operation_actor_user_id!(attrs, actor_id),
               device_id: owner_id!(attrs),
               principal_id: Map.get(attrs, :principal_id),
               signing_key_id: document_operation_signing_key_id!(purpose, attrs)
             }
           }
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        Repo.rollback(reason)
    end
  rescue
    ArgumentError -> Repo.rollback(:invalid_signature)
  end

  defp document_operation_signing_key_id!("document_update", attrs),
    do: Map.fetch!(attrs, :signing_key_id)

  defp document_operation_signing_key_id!("document_snapshot", attrs),
    do: Map.fetch!(attrs, :created_by_signing_key_id)

  defp document_operation_ciphertext!("document_update", attrs),
    do: Map.fetch!(attrs, :update_data)

  defp document_operation_ciphertext!("document_snapshot", attrs), do: Map.fetch!(attrs, :data)

  defp document_operation_public_material!(%{owner_kind: "device"} = attrs) do
    case Repo.get(Device, owner_id!(attrs)) do
      %{revoked_at: nil, hybrid_signing_public_key_material: material} when is_map(material) ->
        material

      _ ->
        raise ArgumentError, "document_operation_signer_invalid"
    end
  end

  defp document_operation_public_material!(
         %{
           owner_kind: "share_participant_device"
         } = attrs
       ) do
    case Sharing.participant_signing_public_material(owner_id!(attrs)) do
      {:ok, material} ->
        material

      _ ->
        raise ArgumentError, "document_operation_signer_invalid"
    end
  end

  defp document_operation_public_material!(_),
    do: raise(ArgumentError, "owner_kind_invalid")

  defp document_operation_actor_user_id!(
         %{owner_kind: "share_participant_device"} = attrs,
         _actor_id
       ),
       do: Map.fetch!(attrs, :principal_id)

  defp document_operation_actor_user_id!(_attrs, actor_id), do: actor_id

  defp owner_id!(attrs), do: Map.fetch!(attrs, :owner_id)

  defp authority_boundary!(attrs, event_type) do
    payload = admission_payload!(attrs, event_type)
    body = Map.fetch!(payload, "body")

    if event_type == "document_write_session_admitted" do
      %{
        "document_permission_proof_hash" => Map.fetch!(body, "document_permission_proof_hash"),
        "min_dek_version" => Map.fetch!(body, "min_dek_version"),
        "write_session_counter" => Map.fetch!(attrs, :write_session_counter),
        "write_session_event_hash" =>
          get_in(attrs, [:public_data, "writeSessionEventHash"]) ||
            Hash.blake3_base64url(JCS.canonical_bytes!(payload)),
        "write_session_id" => body["session_id"] || Map.fetch!(body, "write_session_id")
      }
    else
      %{
        "admission_event_type" => event_type,
        "admission_nonce" => Map.fetch!(body, "admission_nonce"),
        "document_permission_proof_hash" => Map.fetch!(body, "document_permission_proof_hash"),
        "min_dek_version" => Map.fetch!(body, "min_dek_version"),
        "previous_workspace_event_hash" => Map.fetch!(body, "previous_workspace_event_hash"),
        "previous_workspace_event_sequence" =>
          Map.fetch!(body, "previous_workspace_event_sequence")
      }
    end
  end

  defp admission_payload!(attrs, event_type) do
    attrs
    |> Map.fetch!(:admission)
    |> Map.fetch!("workspaceKeyDirectoryEvents")
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => ^event_type} = payload} -> payload
      _ -> nil
    end)
    |> case do
      nil -> raise ArgumentError, "document_admission_event_missing"
      payload -> payload
    end
  end

  @rbac_write_check_sql """
  SELECT EXISTS(
    SELECT 1 FROM workspace_members wm
    JOIN workspace_roles wr ON wr.id = wm.role_id
    WHERE wm.workspace_id = $1 AND wm.user_id = $2
    AND (
      wr.base_role = 'owner'
      OR (
        wr.base_role IN ('admin', 'editor')
        AND (
          EXISTS (
            SELECT 1 FROM workspace_role_permissions wrp
            WHERE wrp.role_id = wm.role_id
              AND wrp.permission = 'document:write'
              AND wrp.granted = true
          )
          OR (
            NOT EXISTS (
              SELECT 1 FROM workspace_role_permissions wrp
              WHERE wrp.role_id = wm.role_id
                AND wrp.permission = 'document:write'
            )
            AND NOT (
              wr.catalog_version IS NOT NULL
              AND wr.catalog_version < 1
            )
          )
        )
      )
    )
  )
  """

  defp validate_write_permission!(
         document,
         _actor_id,
         %{session_kind: :share_participant} = attrs
       ) do
    if Map.fetch!(attrs, :grant) == "edit" and
         Sharing.can_write_document?(Map.fetch!(attrs, :share_id), document.id) do
      :ok
    else
      Repo.rollback(:permission_denied)
    end
  end

  defp validate_write_permission!(
         %{id: document_id, workspace_id: workspace_id},
         actor_id,
         _attrs
       ) do
    document = %Document{id: document_id, workspace_id: workspace_id}

    case Workspaces.authorize_guest_permission(
           workspace_id,
           actor_id,
           "document:write",
           document
         ) do
      :ok ->
        :ok

      {:error, _reason} ->
        {:ok, result} =
          Repo.query(@rbac_write_check_sql, [
            Ecto.UUID.dump!(workspace_id),
            Ecto.UUID.dump!(actor_id)
          ])

        unless result.rows == [[true]] do
          Repo.rollback(:permission_denied)
        end
    end
  end

  defp update_snapshot_metadata(
         snapshot_id,
         authority_context_key,
         signing_key_id,
         clock,
         version
       ) do
    clock_key = "#{authority_context_key}:#{signing_key_id}"

    Repo.query!(
      """
      UPDATE document_snapshots
      SET
        clocks = jsonb_set(
          COALESCE(clocks, '{}'::jsonb),
          $1,
          to_jsonb(GREATEST(COALESCE((clocks ->> $2)::integer, -1), $3::integer)),
          true
        ),
        latest_version = GREATEST(COALESCE(latest_version, 0), $4::integer)
      WHERE id = $5
      """,
      [
        [clock_key],
        clock_key,
        clock,
        version,
        Ecto.UUID.dump!(snapshot_id)
      ]
    )
  end

  defp get_existing_by_hash(document_id, update_hash) do
    from(u in DocumentUpdate,
      where: u.document_id == ^document_id and u.update_hash == ^update_hash,
      limit: 1
    )
    |> Repo.one()
  end

  defp cas_update_active_snapshot(document_id, new_snapshot_id, parent_snapshot_id) do
    doc_id = Ecto.UUID.dump!(document_id)
    new_id = Ecto.UUID.dump!(new_snapshot_id)

    {sql, params} =
      if parent_snapshot_id do
        {"UPDATE documents SET active_snapshot_id = $1 WHERE id = $2 AND active_snapshot_id = $3",
         [new_id, doc_id, Ecto.UUID.dump!(parent_snapshot_id)]}
      else
        {"UPDATE documents SET active_snapshot_id = $1 WHERE id = $2 AND active_snapshot_id IS NULL",
         [new_id, doc_id]}
      end

    %{num_rows: num_rows} = Repo.query!(sql, params)
    num_rows
  end

  defp build_recovery_data(document) do
    snapshot =
      if document.active_snapshot_id,
        do: Repo.get(DocumentSnapshot, document.active_snapshot_id)

    updates =
      if snapshot,
        do:
          from(u in DocumentUpdate,
            where: u.document_id == ^document.id and u.snapshot_id == ^snapshot.id,
            order_by: [asc: u.version]
          )
          |> Repo.all(),
        else: []

    %{snapshot: snapshot, updates: updates}
  end

  defp build_recovery_data_outside_tx(document_id) do
    case Repo.get(Document, document_id) do
      nil ->
        nil

      document ->
        build_recovery_data(%{
          id: document.id,
          active_snapshot_id: document.active_snapshot_id
        })
    end
  end

  # ── Serializable Transaction Retry ──────────────

  @serializable_max_retries 3

  defp with_serializable_retry(fun, attempt \\ 1) do
    Repo.transaction(fn ->
      Repo.query!("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
      fun.()
    end)
  rescue
    e in Postgrex.Error ->
      serializable_error? =
        e.postgres != nil and
          e.postgres.code in [
            "40001",
            "40P01",
            :serialization_failure,
            :deadlock_detected
          ]

      if serializable_error? and attempt < @serializable_max_retries do
        Process.sleep(Enum.random(5..25))
        with_serializable_retry(fun, attempt + 1)
      else
        if serializable_error? do
          {:error, :serialization_conflict}
        else
          reraise e, __STACKTRACE__
        end
      end
  end
end
