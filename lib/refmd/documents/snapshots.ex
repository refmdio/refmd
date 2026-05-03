defmodule RefMD.Documents.Snapshots do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.{Document, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces

  # Clocks are snapshot-scoped: each new snapshot starts with no accumulated
  # per-device clocks. Pre-snapshot clocks are captured in parent_snapshot_update_clocks.
  # update_snapshot_metadata populates this field as updates arrive.
  @initial_snapshot_clocks %{}

  # ── Snapshot Proof Chain ─────────────────────────

  # No pin: first connection, no ancestry proof needed.
  # Same snapshot: no change, empty chain.
  # Different snapshots: traverse parent_snapshot_id from active to pinned.
  # Not ancestor: pinned snapshot not on ancestry path, return empty (client fail-closed).
  @spec build_snapshot_proof_chain(Ecto.UUID.t(), Ecto.UUID.t() | nil, Ecto.UUID.t() | nil) ::
          [map()]
  def build_snapshot_proof_chain(_document_id, nil, _active_snapshot_id), do: []
  def build_snapshot_proof_chain(_document_id, _pinned, nil), do: []

  def build_snapshot_proof_chain(_document_id, pinned_snapshot_id, active_snapshot_id)
      when pinned_snapshot_id == active_snapshot_id,
      do: []

  @proof_chain_cte_sql """
  WITH RECURSIVE chain AS (
    SELECT id, parent_snapshot_id, ciphertext_hash, parent_snapshot_proof, 0 AS depth
    FROM document_snapshots
    WHERE id = $1 AND document_id = $3
    UNION ALL
    SELECT s.id, s.parent_snapshot_id, s.ciphertext_hash, s.parent_snapshot_proof, c.depth + 1
    FROM document_snapshots s
    JOIN chain c ON s.id = c.parent_snapshot_id
    WHERE s.id != $2 AND s.document_id = $3
  )
  SELECT id, parent_snapshot_id, ciphertext_hash, parent_snapshot_proof FROM chain
  ORDER BY depth DESC
  """

  def build_snapshot_proof_chain(document_id, pinned_snapshot_id, active_snapshot_id) do
    result =
      Repo.query(
        @proof_chain_cte_sql,
        [
          Ecto.UUID.dump!(active_snapshot_id),
          Ecto.UUID.dump!(pinned_snapshot_id),
          Ecto.UUID.dump!(document_id)
        ]
      )

    format_proof_chain(result, pinned_snapshot_id)
  end

  defp format_proof_chain({:ok, %{rows: [[_id, oldest_parent, _h, _p] | _] = rows}}, pinned_id) do
    if oldest_parent == Ecto.UUID.dump!(pinned_id) do
      Enum.map(rows, fn [id, _parent, ciphertext_hash, parent_snapshot_proof] ->
        %{
          snapshotId: Ecto.UUID.load!(id),
          ciphertextHash: ciphertext_hash,
          parentSnapshotProof: parent_snapshot_proof
        }
      end)
    else
      []
    end
  end

  defp format_proof_chain(_, _), do: []

  # ── Save Update ─────────────────────────────────

  @spec save_update(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def save_update(document_id, actor_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_not_archived!(document)
      validate_write_permission!(document, actor_id, attrs)
      validate_device_active!(actor_id, attrs)

      ref_snapshot_id = attrs.ref_snapshot_id

      if is_nil(document.active_snapshot_id) do
        Repo.rollback(:snapshot_mismatch)
      end

      if document.active_snapshot_id != ref_snapshot_id do
        Repo.rollback(:snapshot_mismatch)
      end

      if attrs.key_version < document.min_dek_version do
        Repo.rollback(:key_version_too_old)
      end

      case insert_update_atomic(document_id, ref_snapshot_id, attrs) do
        %{duplicate: true} = result ->
          result

        result ->
          record_document_signer!(document_id, actor_id, attrs)
          result
      end
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Save Snapshot ──────────────────────────────

  @spec save_snapshot(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom(), map() | nil}
  def save_snapshot(document_id, actor_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_not_archived!(document)
      validate_write_permission!(document, actor_id, attrs)
      validate_device_active!(actor_id, attrs)

      latest_version = validate_snapshot_preconditions!(document, attrs)

      snapshot_id = attrs.snapshot_id

      insert_snapshot!(document_id, snapshot_id, latest_version, attrs)
      record_document_signer!(document_id, actor_id, attrs)

      cas_result =
        cas_update_active_snapshot(document_id, snapshot_id, attrs.parent_snapshot_id)

      if cas_result == 0 do
        Repo.rollback({:parent_mismatch, build_recovery_data(document)})
      end

      maybe_clear_rotation_snapshot(document, document_id, attrs.key_version)

      %{snapshot_id: snapshot_id, latest_version: latest_version}
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
    document_id, snapshot_id, device_id, clock, version,
    device_signing_pub_key, update_data, nonce, key_version,
    update_hash, signature, timestamp, created_at
  )
  SELECT $1, $2, $3, $4,
    COALESCE((SELECT MAX(version) FROM document_updates WHERE document_id = $1), 0) + 1,
    $5, $6, $7, $8, $9, $10, $11, NOW()
  WHERE $4 = COALESCE(
    (SELECT MAX(clock) + 1 FROM document_updates WHERE snapshot_id = $2 AND device_signing_pub_key = $5), 0
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
          Ecto.UUID.dump!(attrs.device_id),
          attrs.clock,
          attrs.device_signing_pub_key,
          attrs.update_data,
          attrs.nonce,
          attrs.key_version,
          attrs.update_hash,
          attrs.signature,
          attrs.timestamp
        ]
      )

    case result.rows do
      [[version]] ->
        update_snapshot_metadata(
          ref_snapshot_id,
          attrs.device_signing_pub_key,
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
      if attrs.parent_snapshot_proof != "" or attrs.parent_snapshot_update_clocks != %{} do
        Repo.rollback({:invalid_genesis, nil})
      end
    else
      verify_parent_snapshot_proof!(document, attrs)
    end
  end

  defp verify_parent_snapshot_proof!(document, attrs) do
    parent = Repo.get(DocumentSnapshot, document.active_snapshot_id)

    if is_nil(parent) do
      Repo.rollback({:parent_mismatch, build_recovery_data(document)})
    end

    expected_proof = compute_parent_snapshot_proof(parent)

    unless attrs.parent_snapshot_proof == expected_proof do
      Repo.rollback({:parent_mismatch, build_recovery_data(document)})
    end
  end

  defp compute_parent_snapshot_proof(parent_snapshot) do
    proof_input = %{
      "ciphertext_hash" => parent_snapshot.ciphertext_hash,
      "parent_proof" => parent_snapshot.parent_snapshot_proof,
      "snapshot_id" => parent_snapshot.id
    }

    RefMD.Crypto.jcs_canonicalize(proof_input)
    |> Blake3.hash_base64url()
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
    if attrs.key_version < document.min_dek_version do
      Repo.rollback({:key_version_too_old, build_recovery_data(document)})
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
        from(d in Document, where: d.id == ^document_id)
        |> Repo.update_all(set: [needs_rotation_snapshot: false])
      end
    end
  end

  defp insert_snapshot!(document_id, snapshot_id, latest_version, attrs) do
    changeset =
      DocumentSnapshot.changeset(%DocumentSnapshot{}, %{
        id: snapshot_id,
        document_id: document_id,
        parent_snapshot_id: attrs.parent_snapshot_id,
        device_id: attrs.device_id,
        latest_version: latest_version,
        data: attrs.data,
        nonce: attrs.nonce,
        key_version: attrs.key_version,
        signature: attrs.signature,
        ciphertext_hash: Blake3.hash_base64url(attrs.data),
        clocks: @initial_snapshot_clocks,
        parent_snapshot_update_clocks: attrs.parent_snapshot_update_clocks,
        parent_snapshot_proof: attrs.parent_snapshot_proof,
        created_by_device: attrs.created_by_device
      })

    case Repo.insert(changeset) do
      {:ok, snapshot} -> snapshot
      {:error, _cs} -> Repo.rollback({:insert_failed, nil})
    end
  end

  # ── Save Helpers ───────────────────────────────

  defp lock_document(document_id) do
    case Repo.query(
           "SELECT id, workspace_id, active_snapshot_id, archived_at, min_dek_version, needs_rotation_snapshot FROM documents WHERE id = $1 FOR UPDATE",
           [Ecto.UUID.dump!(document_id)]
         ) do
      {:ok, %{rows: [row]}} ->
        [
          id,
          workspace_id,
          active_snapshot_id,
          archived_at,
          min_dek_version,
          needs_rotation_snapshot
        ] =
          row

        %{
          id: Ecto.UUID.load!(id),
          workspace_id: Ecto.UUID.load!(workspace_id),
          active_snapshot_id: if(active_snapshot_id, do: Ecto.UUID.load!(active_snapshot_id)),
          archived_at: archived_at,
          min_dek_version: min_dek_version,
          needs_rotation_snapshot: needs_rotation_snapshot
        }

      _ ->
        Repo.rollback(:document_not_found)
    end
  end

  defp validate_not_archived!(%{archived_at: nil}), do: :ok
  defp validate_not_archived!(%{archived_at: _}), do: Repo.rollback(:document_archived)

  defp validate_device_active!(_actor_id, %{session_kind: :share_participant} = attrs) do
    principal_id = Map.fetch!(attrs, :principal_id)
    validate_share_device_active!(principal_id, attrs.device_id)
  end

  defp validate_device_active!(actor_id, %{session_kind: :mounted_share} = attrs) do
    validate_member_device_active!(actor_id, attrs.device_id)
  end

  defp validate_device_active!(_actor_id, attrs) do
    validate_member_device_not_revoked!(attrs.device_id)
  end

  defp validate_member_device_active!(actor_id, device_id) do
    result =
      Repo.query(
        "SELECT 1 FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR SHARE",
        [Ecto.UUID.dump!(device_id), Ecto.UUID.dump!(actor_id)]
      )

    case result do
      {:ok, %{num_rows: 1}} -> :ok
      _ -> Repo.rollback(:device_revoked)
    end
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
    result =
      Repo.query(
        "SELECT 1 FROM share_participant_devices WHERE id = $1 AND principal_id = $2 FOR SHARE",
        [Ecto.UUID.dump!(device_id), Ecto.UUID.dump!(principal_id)]
      )

    case result do
      {:ok, %{num_rows: 1}} -> :ok
      _ -> Repo.rollback(:device_revoked)
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
         document,
         _actor_id,
         %{session_kind: :mounted_share} = attrs
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

  defp record_document_signer!(
         document_id,
         _actor_id,
         %{session_kind: :share_participant} = attrs
       ) do
    principal_id = Map.fetch!(attrs, :principal_id)
    share_id = Map.fetch!(attrs, :share_id)

    signer =
      Repo.query!(
        """
        SELECT d.id, d.signing_public_key, d.encryption_public_key
        FROM share_participant_devices d
        WHERE d.id = $1 AND d.principal_id = $2 AND d.share_id = $3
        """,
        [
          Ecto.UUID.dump!(attrs.device_id),
          Ecto.UUID.dump!(principal_id),
          Ecto.UUID.dump!(share_id)
        ]
      )

    case signer.rows do
      [[device_id, signing_public_key, encryption_public_key]] ->
        upsert_document_signer!(%{
          document_id: document_id,
          signer_kind: "share_participant",
          share_id: share_id,
          principal_id: principal_id,
          user_id: nil,
          device_id: Ecto.UUID.load!(device_id),
          signing_public_key: signing_public_key,
          encryption_public_key: encryption_public_key
        })

      _ ->
        Repo.rollback(:device_revoked)
    end
  end

  defp record_document_signer!(document_id, actor_id, %{session_kind: :mounted_share} = attrs) do
    share_id = Map.fetch!(attrs, :share_id)

    record_member_document_signer!(
      document_id,
      actor_id,
      attrs.device_id,
      "mounted_share",
      share_id
    )
  end

  defp record_document_signer!(document_id, actor_id, attrs) do
    record_member_document_signer!(document_id, actor_id, attrs.device_id, "workspace", nil)
  end

  defp record_member_document_signer!(document_id, user_id, device_id, signer_kind, share_id) do
    signer =
      Repo.query!(
        """
        SELECT d.id, d.signing_public_key, d.ecdh_public_key
        FROM devices d
        WHERE d.id = $1 AND d.user_id = $2
        """,
        [Ecto.UUID.dump!(device_id), Ecto.UUID.dump!(user_id)]
      )

    case signer.rows do
      [[device_id, signing_public_key, encryption_public_key]] ->
        upsert_document_signer!(%{
          document_id: document_id,
          signer_kind: signer_kind,
          share_id: share_id,
          principal_id: if(signer_kind == "mounted_share", do: user_id),
          user_id: user_id,
          device_id: Ecto.UUID.load!(device_id),
          signing_public_key: signing_public_key,
          encryption_public_key: encryption_public_key
        })

      _ ->
        Repo.rollback(:device_revoked)
    end
  end

  defp upsert_document_signer!(attrs) do
    context_key = document_signer_context_key(attrs)

    Repo.query!(
      """
      INSERT INTO document_signer_keys (
        document_id, signer_kind, share_id, principal_id, user_id, device_id, context_key,
        signing_public_key, encryption_public_key, first_seen_at, last_seen_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
      ON CONFLICT (document_id, signing_public_key, context_key)
      DO UPDATE SET
        last_seen_at = NOW(),
        encryption_public_key = EXCLUDED.encryption_public_key
      """,
      [
        Ecto.UUID.dump!(attrs.document_id),
        attrs.signer_kind,
        dump_optional_uuid(attrs.share_id),
        dump_optional_uuid(attrs.principal_id),
        dump_optional_uuid(attrs.user_id),
        Ecto.UUID.dump!(attrs.device_id),
        context_key,
        attrs.signing_public_key,
        attrs.encryption_public_key
      ]
    )
  end

  defp document_signer_context_key(attrs) do
    [
      attrs.signer_kind,
      attrs.share_id || "-",
      attrs.principal_id || "-",
      attrs.user_id || "-",
      attrs.device_id
    ]
    |> Enum.join(":")
  end

  defp dump_optional_uuid(nil), do: nil
  defp dump_optional_uuid(value), do: Ecto.UUID.dump!(value)

  defp update_snapshot_metadata(snapshot_id, device_signing_pub_key, clock, version) do
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
        [device_signing_pub_key],
        device_signing_pub_key,
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
