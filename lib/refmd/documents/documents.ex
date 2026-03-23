defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.{Changeset, Query}

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.{Document, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Repo

  # Clocks are snapshot-scoped: each new snapshot starts with no accumulated
  # per-device clocks. Pre-snapshot clocks are captured in parent_snapshot_update_clocks.
  # update_snapshot_metadata populates this field as updates arrive.
  @initial_snapshot_clocks %{}

  @max_nesting_depth 10

  # ── Queries ──────────────────────────────────────

  @spec list_documents(Ecto.UUID.t()) :: [Document.t()]
  def list_documents(workspace_id) do
    from(d in Document,
      where: d.workspace_id == ^workspace_id,
      order_by: [asc: d.position]
    )
    |> Repo.all()
  end

  @spec get_document(Ecto.UUID.t()) :: Document.t() | nil
  def get_document(id), do: Repo.get(Document, id)

  @spec get_document!(Ecto.UUID.t()) :: Document.t()
  def get_document!(id), do: Repo.get!(Document, id)

  @spec get_active_snapshot(Ecto.UUID.t()) :: DocumentSnapshot.t() | nil
  def get_active_snapshot(document_id) do
    from(d in Document,
      where: d.id == ^document_id,
      select: d.active_snapshot_id
    )
    |> Repo.one()
    |> case do
      nil -> nil
      snapshot_id -> Repo.get(DocumentSnapshot, snapshot_id)
    end
  end

  # Single-statement initial document data fetch with inline RBAC.
  # One SQL = one MVCC snapshot = no TOCTOU between snapshot and updates fetch.
  # Returns 0 rows if user lacks document:read, 1 row otherwise.
  @initial_document_data_sql """
  WITH authorized_document AS (
    SELECT d.id AS document_id, d.active_snapshot_id
    FROM documents d
    JOIN workspace_members wm
      ON wm.workspace_id = d.workspace_id AND wm.user_id = $3
    JOIN workspace_roles wr
      ON wr.id = wm.role_id
    LEFT JOIN workspace_role_permissions wrp
      ON wrp.role_id = wr.id AND wrp.permission = 'document:read'
    WHERE d.id = $1 AND d.workspace_id = $2
      AND CASE
            WHEN wr.base_role = 'owner' THEN TRUE
            WHEN wrp.granted IS NOT NULL THEN wrp.granted
            WHEN wr.catalog_version IS NOT NULL AND wr.catalog_version < 1 THEN FALSE
            ELSE TRUE
          END
  )
  SELECT
    s.id, s.document_id, s.parent_snapshot_id, s.device_id,
    s.latest_version, s.data, s.nonce, s.key_version,
    s.signature, s.ciphertext_hash, s.clocks,
    s.parent_snapshot_update_clocks, s.parent_snapshot_proof,
    s.created_by_device, s.created_at,
    COALESCE(u.updates_json, '[]'::jsonb) AS updates_json
  FROM authorized_document ad
  LEFT JOIN document_snapshots s
    ON s.id = ad.active_snapshot_id AND s.document_id = ad.document_id
  LEFT JOIN LATERAL (
    SELECT jsonb_agg(
      jsonb_build_object(
        'id', du.id,
        'document_id', du.document_id,
        'snapshot_id', du.snapshot_id,
        'device_id', du.device_id,
        'clock', du.clock,
        'version', du.version,
        'device_signing_pub_key', du.device_signing_pub_key,
        'update_data', encode(du.update_data, 'base64'),
        'nonce', encode(du.nonce, 'base64'),
        'key_version', du.key_version,
        'update_hash', du.update_hash,
        'signature', CASE WHEN du.signature IS NOT NULL THEN encode(du.signature, 'base64') END,
        'mac', CASE WHEN du.mac IS NOT NULL THEN encode(du.mac, 'base64') END,
        'share_id', du.share_id,
        'timestamp', du.timestamp
      ) ORDER BY du.version
    ) AS updates_json
    FROM document_updates du
    WHERE du.document_id = ad.document_id
      AND du.snapshot_id = ad.active_snapshot_id
  ) u ON TRUE
  """

  @spec get_initial_document_data(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {DocumentSnapshot.t() | nil, [map()]} | nil
  @spec get_initial_document_data(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, {DocumentSnapshot.t() | nil, [map()]}} | {:error, :unauthorized | :db_error}
  def get_initial_document_data(document_id, workspace_id, user_id) do
    case Repo.query(
           @initial_document_data_sql,
           [Ecto.UUID.dump!(document_id), Ecto.UUID.dump!(workspace_id), Ecto.UUID.dump!(user_id)]
         ) do
      {:ok, %{rows: [row], columns: columns}} ->
        {:ok, parse_initial_data_row(row, columns)}

      {:ok, %{rows: []}} ->
        {:error, :unauthorized}

      {:error, _} ->
        {:error, :db_error}
    end
  end

  defp parse_initial_data_row(row, columns) do
    row_map = Enum.zip(columns, row) |> Map.new()

    snapshot =
      case row_map["id"] do
        nil ->
          nil

        _ ->
          %DocumentSnapshot{
            id: Ecto.UUID.load!(row_map["id"]),
            document_id: Ecto.UUID.load!(row_map["document_id"]),
            parent_snapshot_id:
              if(row_map["parent_snapshot_id"],
                do: Ecto.UUID.load!(row_map["parent_snapshot_id"])
              ),
            device_id: Ecto.UUID.load!(row_map["device_id"]),
            latest_version: row_map["latest_version"],
            data: row_map["data"],
            nonce: row_map["nonce"],
            key_version: row_map["key_version"],
            signature: row_map["signature"],
            ciphertext_hash: row_map["ciphertext_hash"],
            clocks: row_map["clocks"],
            parent_snapshot_update_clocks: row_map["parent_snapshot_update_clocks"],
            parent_snapshot_proof: row_map["parent_snapshot_proof"],
            created_by_device: row_map["created_by_device"],
            created_at: row_map["created_at"]
          }
      end

    updates_json = row_map["updates_json"] || []

    updates =
      Enum.map(updates_json, fn u ->
        uuid_load = fn
          nil -> nil
          val when is_binary(val) -> val
        end

        %{
          document_id: uuid_load.(u["document_id"]),
          snapshot_id: uuid_load.(u["snapshot_id"]),
          device_id: uuid_load.(u["device_id"]),
          clock: u["clock"],
          version: u["version"],
          device_signing_pub_key: u["device_signing_pub_key"],
          update_data: Base.decode64!(u["update_data"], ignore: :whitespace),
          nonce: Base.decode64!(u["nonce"], ignore: :whitespace),
          key_version: u["key_version"],
          update_hash: u["update_hash"],
          signature: if(u["signature"], do: Base.decode64!(u["signature"], ignore: :whitespace)),
          mac: if(u["mac"], do: Base.decode64!(u["mac"], ignore: :whitespace)),
          share_id: u["share_id"],
          timestamp: u["timestamp"]
        }
      end)

    {snapshot, updates}
  end

  @spec list_updates_for_snapshot(Ecto.UUID.t(), Ecto.UUID.t()) :: [DocumentUpdate.t()]
  def list_updates_for_snapshot(document_id, snapshot_id) do
    from(u in DocumentUpdate,
      where: u.document_id == ^document_id and u.snapshot_id == ^snapshot_id,
      order_by: [asc: u.version]
    )
    |> Repo.all()
  end

  @spec list_updates_after_clocks(Ecto.UUID.t(), Ecto.UUID.t(), map()) :: [DocumentUpdate.t()]
  def list_updates_after_clocks(document_id, snapshot_id, known_clocks) do
    updates = list_updates_for_snapshot(document_id, snapshot_id)

    Enum.filter(updates, fn update ->
      case update.device_signing_pub_key do
        nil ->
          true

        pub_key ->
          known_clock = Map.get(known_clocks, pub_key, -1)
          is_nil(update.clock) or update.clock > known_clock
      end
    end)
  end

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
  def save_update(document_id, user_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_not_archived!(document)
      validate_write_permission!(document.workspace_id, user_id)
      validate_device_not_revoked!(attrs.device_id)

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

      insert_update_atomic(document_id, ref_snapshot_id, attrs)
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Save Snapshot ──────────────────────────────

  @spec save_snapshot(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, atom(), map() | nil}
  def save_snapshot(document_id, user_id, attrs) do
    with_serializable_retry(fn ->
      document = lock_document(document_id)
      validate_not_archived!(document)
      validate_write_permission!(document.workspace_id, user_id)
      validate_device_not_revoked!(attrs.device_id)

      latest_version = validate_snapshot_preconditions!(document, attrs)

      snapshot_id = attrs.snapshot_id

      insert_snapshot!(document_id, snapshot_id, latest_version, attrs)

      cas_result =
        cas_update_active_snapshot(document_id, snapshot_id, attrs.parent_snapshot_id)

      if cas_result == 0 do
        Repo.rollback({:parent_mismatch, build_recovery_data(document)})
      end

      maybe_clear_rotation_snapshot(document, document_id, attrs.key_version)

      %{snapshot_id: snapshot_id}
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

        %{snapshot_id: ref_snapshot_id, clock: attrs.clock, version: version}

      [] ->
        case get_existing_by_hash(document_id, attrs.update_hash) do
          nil ->
            Repo.rollback(:clock_mismatch)

          existing ->
            %{
              snapshot_id: existing.snapshot_id,
              clock: existing.clock,
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

  defp validate_device_not_revoked!(device_id) do
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

  defp validate_write_permission!(workspace_id, user_id) do
    {:ok, result} =
      Repo.query(@rbac_write_check_sql, [
        Ecto.UUID.dump!(workspace_id),
        Ecto.UUID.dump!(user_id)
      ])

    unless result.rows == [[true]] do
      Repo.rollback(:permission_denied)
    end
  end

  defp update_snapshot_metadata(snapshot_id, device_signing_pub_key, clock, version) do
    Repo.query!(
      "UPDATE document_snapshots SET clocks = jsonb_set(COALESCE(clocks, '{}'::jsonb), $1, to_jsonb($2::integer)), latest_version = $3 WHERE id = $4",
      [
        [device_signing_pub_key],
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
        do: list_updates_for_snapshot(document.id, snapshot.id),
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
        e.postgres != nil and e.postgres.code in ["40001", "40P01"]

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

  # ── Create ───────────────────────────────────────

  @spec create_document(map()) :: {:ok, Document.t()} | {:error, Ecto.Changeset.t()}
  def create_document(attrs) do
    doc_type = get_attr(attrs, :doc_type)
    encrypted_title = get_attr(attrs, :encrypted_title)
    title = get_attr(attrs, :title)
    workspace_id = get_attr(attrs, :workspace_id)
    parent_id = get_attr(attrs, :parent_id)

    is_encrypted = doc_type != "folder" && encrypted_title != nil
    position = next_position(workspace_id, parent_id)
    slug_source = if is_encrypted, do: "untitled", else: title || "untitled"
    slug = generate_slug(slug_source)

    enriched =
      attrs
      |> Map.put("is_encrypted", is_encrypted)
      |> Map.put("position", position)
      |> Map.put("slug", slug)

    base =
      case get_attr(attrs, :id) do
        nil -> %Document{}
        id -> %Document{id: id}
      end

    base
    |> Document.changeset(enriched)
    |> validate_parent_constraints()
    |> validate_create_depth()
    |> Repo.insert()
  end

  # ── Update ───────────────────────────────────────

  @spec update_document(Document.t(), map()) ::
          {:ok, Document.t()} | {:error, Ecto.Changeset.t() | :document_archived}
  def update_document(%Document{archived_at: archived_at}, _attrs)
      when not is_nil(archived_at) do
    {:error, :document_archived}
  end

  def update_document(%Document{} = document, attrs) do
    result =
      document
      |> Document.changeset(attrs)
      |> validate_parent_constraints()
      |> validate_parent_change(document.id)
      |> Repo.update()

    result
  end

  # ── Delete ───────────────────────────────────────

  @spec delete_document(Document.t()) ::
          {:ok, Document.t()} | {:error, Ecto.Changeset.t() | :folder_not_empty}
  def delete_document(%Document{} = document) do
    if document.doc_type == "folder" && has_children?(document.id) do
      {:error, :folder_not_empty}
    else
      Repo.delete(document)
    end
  end

  # ── Reorder ───────────────────────────────────────

  @spec reorder_document(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t() | nil, non_neg_integer()) ::
          {:ok, Document.t()} | {:error, term()}
  def reorder_document(workspace_id, document_id, new_parent_id, new_position) do
    Repo.transaction(fn ->
      document = Repo.get(Document, document_id)

      validate_reorder_preconditions!(document, workspace_id)
      validate_reorder_parent!(new_parent_id, workspace_id)
      validate_reorder_hierarchy!(document, new_parent_id)

      old_parent_id = document.parent_id
      old_position = document.position

      # Step 1: Remove document from current position
      set_temp_position!(document_id)

      # Step 2: Close gap in old parent (shift down — always safe)
      close_position_gap!(workspace_id, old_parent_id, old_position)

      # Step 3: Validate target position is within bounds
      max_pos = count_siblings(workspace_id, new_parent_id)
      target = new_position |> max(0) |> min(max_pos)

      # Step 4: Make room in new parent (shift up — negate trick for constraint safety)
      make_position_room!(workspace_id, new_parent_id, target)

      # Step 5: Set final parent and position
      set_document_parent_position!(document_id, new_parent_id, target)

      Repo.get!(Document, document_id)
    end)
  end

  defp validate_reorder_preconditions!(nil, _workspace_id), do: Repo.rollback(:not_found)

  defp validate_reorder_preconditions!(document, workspace_id) do
    if document.workspace_id != workspace_id, do: Repo.rollback(:not_in_workspace)
    if document.archived_at, do: Repo.rollback(:document_archived)
  end

  defp validate_reorder_parent!(nil, _workspace_id), do: :ok

  defp validate_reorder_parent!(parent_id, workspace_id) do
    case Repo.get(Document, parent_id) do
      nil -> Repo.rollback(:parent_not_found)
      %{doc_type: dt} when dt != "folder" -> Repo.rollback(:parent_not_folder)
      %{workspace_id: ws} when ws != workspace_id -> Repo.rollback(:parent_wrong_workspace)
      %{archived_at: at} when not is_nil(at) -> Repo.rollback(:parent_archived)
      _ -> :ok
    end
  end

  defp validate_reorder_hierarchy!(document, nil), do: document

  defp validate_reorder_hierarchy!(%{id: id}, new_parent_id) when id == new_parent_id do
    Repo.rollback(:circular_reference)
  end

  defp validate_reorder_hierarchy!(document, new_parent_id) do
    {:ok, result} =
      Repo.query(
        """
        WITH RECURSIVE ancestors AS (
          SELECT id, parent_id FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id, d.parent_id FROM documents d
          INNER JOIN ancestors a ON d.id = a.parent_id
        )
        SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $2)
        """,
        [Ecto.UUID.dump!(new_parent_id), Ecto.UUID.dump!(document.id)]
      )

    if result.rows == [[true]], do: Repo.rollback(:circular_reference)

    parent_depth = depth_from_root(new_parent_id)
    sub_depth = subtree_depth(document.id)

    if parent_depth + sub_depth > @max_nesting_depth do
      Repo.rollback(:nesting_too_deep)
    end
  end

  @temp_position -2_147_483_648

  defp set_temp_position!(document_id) do
    Repo.query!(
      "UPDATE documents SET position = $1 WHERE id = $2",
      [@temp_position, Ecto.UUID.dump!(document_id)]
    )
  end

  defp close_position_gap!(workspace_id, parent_id, removed_position) do
    {clause, params} = parent_id_sql(parent_id, 3)

    Repo.query!(
      "UPDATE documents SET position = position - 1 " <>
        "WHERE workspace_id = $1 AND #{clause} AND position > $2",
      [Ecto.UUID.dump!(workspace_id), removed_position | params]
    )
  end

  defp make_position_room!(workspace_id, parent_id, target_position) do
    {clause, params} = parent_id_sql(parent_id, 3)
    ws = Ecto.UUID.dump!(workspace_id)

    # Negate positions >= target to avoid unique constraint violation during shift
    Repo.query!(
      "UPDATE documents SET position = -(position + 1) " <>
        "WHERE workspace_id = $1 AND #{clause} AND position >= $2",
      [ws, target_position | params]
    )

    # Restore to correct positive values
    Repo.query!(
      "UPDATE documents SET position = -position " <>
        "WHERE workspace_id = $1 AND #{clause} AND position < 0 AND position != $2",
      [ws, @temp_position | params]
    )
  end

  defp set_document_parent_position!(document_id, parent_id, position) do
    parent_value = if parent_id, do: Ecto.UUID.dump!(parent_id)

    Repo.query!(
      "UPDATE documents SET parent_id = $1, position = $2, updated_at = $3 WHERE id = $4",
      [parent_value, position, DateTime.utc_now(), Ecto.UUID.dump!(document_id)]
    )
  end

  defp count_siblings(workspace_id, parent_id) do
    {clause, params} = parent_id_sql(parent_id, 2)

    {:ok, result} =
      Repo.query(
        "SELECT count(*) FROM documents WHERE workspace_id = $1 AND #{clause} AND position >= 0",
        [Ecto.UUID.dump!(workspace_id) | params]
      )

    result.rows |> hd() |> hd()
  end

  defp parent_id_sql(nil, _start_param), do: {"parent_id IS NULL", []}

  defp parent_id_sql(parent_id, start_param) do
    {"parent_id = $#{start_param}", [Ecto.UUID.dump!(parent_id)]}
  end

  # ── Archive / Unarchive ──────────────────────────

  @spec archive_document(Document.t()) ::
          {:ok, Document.t()} | {:error, :already_archived}
  def archive_document(%Document{} = document) do
    if document.archived_at do
      {:error, :already_archived}
    else
      now = DateTime.utc_now()

      Repo.query!(
        """
        WITH RECURSIVE descendants AS (
          SELECT id FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id FROM documents d
          INNER JOIN descendants ds ON d.parent_id = ds.id
        )
        UPDATE documents SET archived_at = $2, updated_at = $2
        WHERE id IN (SELECT id FROM descendants)
        """,
        [Ecto.UUID.dump!(document.id), now]
      )

      {:ok, %{document | archived_at: now, updated_at: now}}
    end
  end

  @spec unarchive_document(Document.t()) ::
          {:ok, Document.t()} | {:error, :not_archived | :ancestor_archived}
  def unarchive_document(%Document{} = document) do
    cond do
      is_nil(document.archived_at) ->
        {:error, :not_archived}

      has_archived_ancestor?(document.id) ->
        {:error, :ancestor_archived}

      true ->
        now = DateTime.utc_now()

        Repo.query!(
          """
          WITH RECURSIVE descendants AS (
            SELECT id FROM documents WHERE id = $1
            UNION ALL
            SELECT d.id FROM documents d
            INNER JOIN descendants ds ON d.parent_id = ds.id
          )
          UPDATE documents SET archived_at = NULL, updated_at = $2
          WHERE id IN (SELECT id FROM descendants)
          """,
          [Ecto.UUID.dump!(document.id), now]
        )

        {:ok, %{document | archived_at: nil, updated_at: now}}
    end
  end

  defp has_archived_ancestor?(document_id) do
    {:ok, result} =
      Repo.query(
        """
        WITH RECURSIVE ancestors AS (
          SELECT parent_id FROM documents WHERE id = $1
          UNION ALL
          SELECT d.parent_id FROM documents d
          INNER JOIN ancestors a ON d.id = a.parent_id
          WHERE a.parent_id IS NOT NULL
        )
        SELECT EXISTS(
          SELECT 1 FROM documents d
          INNER JOIN ancestors a ON d.id = a.parent_id
          WHERE d.archived_at IS NOT NULL
        )
        """,
        [Ecto.UUID.dump!(document_id)]
      )

    result.rows |> hd() |> hd()
  end

  # ── Parent Validation ────────────────────────────

  defp validate_parent_constraints(changeset) do
    parent_id = get_field(changeset, :parent_id)
    workspace_id = get_field(changeset, :workspace_id)

    if parent_id do
      case Repo.get(Document, parent_id) do
        nil ->
          add_error(changeset, :parent_id, "parent document not found")

        parent ->
          changeset
          |> validate_parent_is_folder(parent)
          |> validate_same_workspace(parent, workspace_id)
          |> validate_parent_not_archived(parent)
      end
    else
      changeset
    end
  end

  defp validate_parent_is_folder(changeset, parent) do
    if parent.doc_type == "folder" do
      changeset
    else
      add_error(changeset, :parent_id, "parent must be a folder")
    end
  end

  defp validate_same_workspace(changeset, parent, workspace_id) do
    if parent.workspace_id == workspace_id do
      changeset
    else
      add_error(changeset, :parent_id, "parent must be in the same workspace")
    end
  end

  defp validate_parent_not_archived(changeset, parent) do
    if parent.archived_at do
      add_error(changeset, :parent_id, "parent is archived")
    else
      changeset
    end
  end

  # ── Parent Change (Move) Validation ────────────────

  defp validate_parent_change(changeset, document_id) do
    case Map.fetch(changeset.changes, :parent_id) do
      {:ok, nil} ->
        workspace_id = get_field(changeset, :workspace_id)
        new_position = next_position(workspace_id, nil)
        force_change(changeset, :position, new_position)

      {:ok, new_parent_id} ->
        workspace_id = get_field(changeset, :workspace_id)
        new_position = next_position(workspace_id, new_parent_id)

        changeset
        |> force_change(:position, new_position)
        |> validate_no_circular_reference(document_id, new_parent_id)
        |> validate_move_depth(document_id, new_parent_id)

      :error ->
        changeset
    end
  end

  # ── Depth Validation ─────────────────────────────

  defp validate_create_depth(changeset) do
    if changeset.valid? do
      do_validate_create_depth(changeset, get_field(changeset, :parent_id))
    else
      changeset
    end
  end

  defp do_validate_create_depth(changeset, nil), do: changeset

  defp do_validate_create_depth(changeset, parent_id) do
    if depth_from_root(parent_id) + 1 > @max_nesting_depth do
      add_error(changeset, :parent_id, "nesting too deep (max #{@max_nesting_depth} levels)")
    else
      changeset
    end
  end

  defp validate_move_depth(changeset, document_id, new_parent_id) do
    if changeset.valid? do
      parent_depth = depth_from_root(new_parent_id)
      sub_depth = subtree_depth(document_id)

      if parent_depth + sub_depth > @max_nesting_depth do
        add_error(changeset, :parent_id, "nesting too deep (max #{@max_nesting_depth} levels)")
      else
        changeset
      end
    else
      changeset
    end
  end

  defp depth_from_root(parent_id) do
    {:ok, result} =
      Repo.query(
        """
        WITH RECURSIVE ancestors AS (
          SELECT id, parent_id, 1 AS depth FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id, d.parent_id, a.depth + 1 FROM documents d
          INNER JOIN ancestors a ON d.id = a.parent_id
        )
        SELECT max(depth) FROM ancestors
        """,
        [Ecto.UUID.dump!(parent_id)]
      )

    result.rows |> hd() |> hd() || 0
  end

  defp subtree_depth(document_id) do
    {:ok, result} =
      Repo.query(
        """
        WITH RECURSIVE descendants AS (
          SELECT id, 1 AS depth FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id, ds.depth + 1 FROM documents d
          INNER JOIN descendants ds ON d.parent_id = ds.id
        )
        SELECT max(depth) FROM descendants
        """,
        [Ecto.UUID.dump!(document_id)]
      )

    result.rows |> hd() |> hd() || 1
  end

  # ── Circular Reference Check ─────────────────────

  defp validate_no_circular_reference(changeset, document_id, new_parent_id) do
    if changeset.valid? do
      do_check_circular(changeset, document_id, new_parent_id)
    else
      changeset
    end
  end

  defp do_check_circular(changeset, document_id, new_parent_id)
       when document_id == new_parent_id do
    add_error(changeset, :parent_id, "would create circular reference")
  end

  defp do_check_circular(changeset, document_id, new_parent_id) do
    {:ok, result} =
      Repo.query(
        """
        WITH RECURSIVE ancestors AS (
          SELECT id, parent_id FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id, d.parent_id FROM documents d
          INNER JOIN ancestors a ON d.id = a.parent_id
        )
        SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $2)
        """,
        [Ecto.UUID.dump!(new_parent_id), Ecto.UUID.dump!(document_id)]
      )

    case result.rows do
      [[true]] -> add_error(changeset, :parent_id, "would create circular reference")
      [[false]] -> changeset
    end
  end

  # ── Helpers ──────────────────────────────────────

  defp has_children?(document_id) do
    from(d in Document, where: d.parent_id == ^document_id, limit: 1)
    |> Repo.exists?()
  end

  defp next_position(workspace_id, parent_id) do
    query =
      if parent_id do
        from(d in Document,
          where: d.workspace_id == ^workspace_id and d.parent_id == ^parent_id,
          select: fragment("coalesce(max(?), -1) + 1", d.position)
        )
      else
        from(d in Document,
          where: d.workspace_id == ^workspace_id and is_nil(d.parent_id),
          select: fragment("coalesce(max(?), -1) + 1", d.position)
        )
      end

    Repo.one(query)
  end

  defp generate_slug(title) do
    base =
      title
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    base = if base == "", do: "untitled", else: base

    suffix =
      :crypto.strong_rand_bytes(4)
      |> Base.url_encode64(padding: false)
      |> String.downcase()
      |> String.replace("_", "-")
      |> String.replace(~r/-+/, "-")
      |> String.trim("-")

    "#{base}-#{suffix}"
  end

  defp get_attr(attrs, key) when is_atom(key) do
    case Map.fetch(attrs, key) do
      {:ok, val} -> val
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end
end
