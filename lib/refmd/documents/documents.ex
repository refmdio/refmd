defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.{Changeset, Query}

  alias RefMD.Documents.{
    Document,
    DocumentSnapshot,
    DocumentUpdate,
    Ordering,
    WriteStateAdmission
  }

  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces

  @max_nesting_depth 10
  @checkpoint_state_keys ~w(identity_keys device_keys share_participant_keys revoked_key_ids)
  @checkpoint_state_compression "inherit_checkpoint_state_v1"

  # ── Snapshots (delegated to RefMD.Documents.Snapshots) ──

  defdelegate save_update(document_id, user_id, attrs), to: RefMD.Documents.Snapshots
  defdelegate save_snapshot(document_id, user_id, attrs), to: RefMD.Documents.Snapshots
  defdelegate admit_write_session(document_id, user_id, attrs), to: RefMD.Documents.Snapshots

  defdelegate build_snapshot_proof_chain(document_id, pinned_snapshot_id, active_snapshot_id),
    to: RefMD.Documents.Snapshots

  defdelegate publication_sync_allowed?(document, user_id, socket, mounted_share_id),
    to: RefMD.Documents.Access

  defdelegate get_or_start_server(document_id),
    to: RefMD.Documents.Runtime.Server,
    as: :get_or_start

  defdelegate register_connection(document_id, channel_pid), to: RefMD.Documents.Runtime.Server
  defdelegate unregister_connection(document_id, channel_pid), to: RefMD.Documents.Runtime.Server

  defdelegate record_write_session(document_id, payload, expires_at_ms),
    to: RefMD.Documents.Runtime.Server

  defdelegate active_write_sessions(document_id), to: RefMD.Documents.Runtime.Server

  defdelegate set_active_snapshot(document_id, snapshot_id, clocks),
    to: RefMD.Documents.Runtime.Server

  defdelegate update_clocks(document_id, authority_context_key, signing_key_id, clock),
    to: RefMD.Documents.Runtime.Server

  @spec count_combined_siblings(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: non_neg_integer()
  defdelegate count_combined_siblings(workspace_id, parent_id), to: Ordering

  @spec affected_parent_groups_for_document(Ecto.UUID.t()) :: [
          {Ecto.UUID.t(), Ecto.UUID.t() | nil}
        ]
  defdelegate affected_parent_groups_for_document(document_id), to: Ordering

  @spec normalize_combined_siblings!(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: :ok
  defdelegate normalize_combined_siblings!(workspace_id, parent_id), to: Ordering

  @spec normalize_combined_sibling_groups!([{Ecto.UUID.t(), Ecto.UUID.t() | nil}]) :: :ok
  defdelegate normalize_combined_sibling_groups!(groups), to: Ordering

  @spec move_share_mount!(map(), Ecto.UUID.t() | nil, non_neg_integer()) :: :ok
  defdelegate move_share_mount!(mount, parent_id, position), to: Ordering

  @spec document_admission_package!(Ecto.UUID.t(), String.t(), String.t(), keyword()) :: map()
  def document_admission_package!(document_id, event_type, admission_event_hash, opts \\ []) do
    document = get_document(document_id) || raise ArgumentError, "document_required"

    event =
      Encryption.workspace_key_directory_event_by_hash(
        document.workspace_id,
        admission_event_hash
      ) || raise ArgumentError, "document_admission_event_required"

    ensure_document_admission_event_type!(event, event_type)

    checkpoint =
      Encryption.workspace_key_directory_checkpoint_covering_event_head(
        document.workspace_id,
        event.sequence
      ) || raise ArgumentError, "document_admission_checkpoint_required"

    cond do
      Keyword.get(opts, :compact, false) ->
        compact_document_admission_package(event, checkpoint)

      Keyword.has_key?(opts, :from_checkpoint_sequence) ->
        anchored_document_admission_package(document.workspace_id, event, checkpoint, opts)

      Keyword.get(opts, :current_incremental, false) ->
        current_incremental_document_admission_package(document.workspace_id, event, checkpoint)

      Keyword.get(opts, :incremental, false) ->
        incremental_document_admission_package(document.workspace_id, event, checkpoint)

      true ->
        full_document_admission_package(document.workspace_id, event, checkpoint)
    end
  end

  defp ensure_document_admission_event_type!(%{event_type: event_type}, event_type), do: :ok

  defp ensure_document_admission_event_type!(_event, _event_type),
    do: raise(ArgumentError, "document_admission_event_required")

  defp full_document_admission_package(workspace_id, event, checkpoint) do
    current_pin =
      Encryption.current_workspace_key_directory_pin(workspace_id) ||
        raise ArgumentError, "document_admission_pin_required"

    checkpoint_ancestry =
      Encryption.workspace_key_directory_checkpoints_between(
        workspace_id,
        1,
        current_pin.checkpoint_sequence
      )

    event_ancestry =
      Encryption.workspace_key_directory_events_after_until(
        workspace_id,
        0,
        current_pin.event_head_sequence
      )

    %{
      "workspaceKeyDirectoryEvents" => [
        key_directory_envelope(event)
      ],
      "workspaceKeyDirectoryCheckpoint" => key_directory_envelope(checkpoint),
      "workspaceKeyDirectoryCheckpointAncestry" =>
        compressed_checkpoint_ancestry(checkpoint_ancestry),
      "workspaceKeyDirectoryEventAncestry" => Enum.map(event_ancestry, &key_directory_envelope/1)
    }
  end

  defp compact_document_admission_package(event, checkpoint) do
    %{
      "workspaceKeyDirectoryEvents" => [
        key_directory_envelope(event)
      ],
      "workspaceKeyDirectoryCheckpoint" => key_directory_envelope(checkpoint),
      "workspaceKeyDirectoryCheckpointAncestry" => [],
      "workspaceKeyDirectoryEventAncestry" => []
    }
  end

  defp incremental_document_admission_package(workspace_id, event, checkpoint) do
    previous_checkpoint =
      checkpoint.sequence
      |> Kernel.-(1)
      |> then(fn
        sequence when sequence > 0 ->
          workspace_id
          |> Encryption.workspace_key_directory_checkpoints_between(sequence, sequence)
          |> List.first()

        _ ->
          nil
      end)

    previous_event_head_sequence =
      if previous_checkpoint, do: previous_checkpoint.covered_event_head_sequence, else: 0

    event_ancestry =
      Encryption.workspace_key_directory_events_after_until(
        workspace_id,
        previous_event_head_sequence,
        checkpoint.covered_event_head_sequence
      )

    %{
      "workspaceKeyDirectoryEvents" => [
        key_directory_envelope(event)
      ],
      "workspaceKeyDirectoryCheckpoint" => key_directory_envelope(checkpoint),
      "workspaceKeyDirectoryCheckpointAncestry" =>
        previous_checkpoint
        |> List.wrap()
        |> Enum.map(&key_directory_envelope/1),
      "workspaceKeyDirectoryEventAncestry" => Enum.map(event_ancestry, &key_directory_envelope/1)
    }
  end

  defp anchored_document_admission_package(workspace_id, event, checkpoint, opts) do
    with sequence when is_integer(sequence) and sequence > 0 <-
           Keyword.get(opts, :from_checkpoint_sequence),
         hash when is_binary(hash) <- Keyword.get(opts, :from_checkpoint_hash),
         %{checkpoint_hash: ^hash} = anchor <-
           workspace_id
           |> Encryption.workspace_key_directory_checkpoints_between(sequence, sequence)
           |> List.first() do
      bounded_document_admission_package(workspace_id, event, checkpoint, anchor)
    else
      _ -> raise ArgumentError, "document_admission_anchor_required"
    end
  end

  defp bounded_document_admission_package(workspace_id, event, checkpoint, anchor) do
    if anchor.sequence >= checkpoint.sequence do
      candidate_local_document_admission_package(workspace_id, event, checkpoint)
    else
      anchored_bounded_document_admission_package(workspace_id, event, checkpoint, anchor)
    end
  end

  defp anchored_bounded_document_admission_package(workspace_id, event, checkpoint, anchor) do
    checkpoint_ancestry =
      Encryption.workspace_key_directory_checkpoints_between(
        workspace_id,
        anchor.sequence,
        checkpoint.sequence - 1
      )

    event_ancestry =
      Encryption.workspace_key_directory_events_after_until(
        workspace_id,
        anchor.covered_event_head_sequence,
        checkpoint.covered_event_head_sequence
      )

    %{
      "workspaceKeyDirectoryEvents" => [
        key_directory_envelope(event)
      ],
      "workspaceKeyDirectoryCheckpoint" => key_directory_envelope(checkpoint),
      "workspaceKeyDirectoryCheckpointAncestry" =>
        compressed_checkpoint_ancestry(checkpoint_ancestry),
      "workspaceKeyDirectoryEventAncestry" => Enum.map(event_ancestry, &key_directory_envelope/1)
    }
  end

  defp current_incremental_document_admission_package(workspace_id, event, checkpoint) do
    candidate_local_document_admission_package(workspace_id, event, checkpoint)
  end

  defp candidate_local_document_admission_package(workspace_id, event, checkpoint) do
    previous_checkpoint = previous_checkpoint(workspace_id, checkpoint)
    start_event_head_sequence = previous_checkpoint_event_head_sequence(previous_checkpoint)

    event_ancestry =
      Encryption.workspace_key_directory_events_after_until(
        workspace_id,
        start_event_head_sequence,
        checkpoint.covered_event_head_sequence
      )

    %{
      "workspaceKeyDirectoryEvents" => [
        key_directory_envelope(event)
      ],
      "workspaceKeyDirectoryCheckpoint" => key_directory_envelope(checkpoint),
      "workspaceKeyDirectoryCheckpointAncestry" =>
        previous_checkpoint
        |> List.wrap()
        |> Enum.map(&key_directory_envelope/1),
      "workspaceKeyDirectoryEventAncestry" => Enum.map(event_ancestry, &key_directory_envelope/1)
    }
  end

  defp previous_checkpoint(workspace_id, %{sequence: sequence}) when sequence > 1 do
    workspace_id
    |> Encryption.workspace_key_directory_checkpoints_between(sequence - 1, sequence - 1)
    |> List.first()
  end

  defp previous_checkpoint(_workspace_id, _checkpoint), do: nil

  defp previous_checkpoint_event_head_sequence(nil), do: 0

  defp previous_checkpoint_event_head_sequence(previous_checkpoint),
    do: previous_checkpoint.covered_event_head_sequence

  defp compressed_checkpoint_ancestry(checkpoints, anchor_payload \\ nil) do
    {envelopes, _previous_payload} =
      Enum.reduce(checkpoints, {[], anchor_payload}, fn checkpoint, {acc, previous_payload} ->
        envelope = key_directory_envelope(checkpoint, previous_payload)
        {[envelope | acc], checkpoint.payload}
      end)

    Enum.reverse(envelopes)
  end

  defp key_directory_envelope(envelope) do
    %{
      "payload" => envelope.payload,
      "signatures" => envelope.signatures
    }
  end

  defp key_directory_envelope(envelope, previous_payload) when is_map(previous_payload) do
    if checkpoint_state_equal?(envelope.payload, previous_payload) do
      %{
        "payload" => Map.drop(envelope.payload, @checkpoint_state_keys),
        "payloadStateCompression" => @checkpoint_state_compression,
        "signatures" => envelope.signatures
      }
    else
      key_directory_envelope(envelope)
    end
  end

  defp key_directory_envelope(envelope, _previous_payload), do: key_directory_envelope(envelope)

  defp checkpoint_state_equal?(payload, previous_payload) do
    Enum.all?(@checkpoint_state_keys, fn key ->
      Map.get(payload, key, []) == Map.get(previous_payload, key, [])
    end)
  end

  # ── Reordering (delegated to RefMD.Documents.Reordering) ──

  defdelegate reorder_document(workspace_id, document_id, new_parent_id, new_position),
    to: RefMD.Documents.Reordering

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

  @spec get_snapshot(Ecto.UUID.t()) :: DocumentSnapshot.t() | nil
  def get_snapshot(snapshot_id), do: Repo.get(DocumentSnapshot, snapshot_id)

  @spec get_update_by_hash(Ecto.UUID.t(), String.t()) :: DocumentUpdate.t() | nil
  def get_update_by_hash(document_id, update_hash) do
    from(u in DocumentUpdate,
      where: u.document_id == ^document_id and u.update_hash == ^update_hash,
      limit: 1
    )
    |> Repo.one()
  end

  # Single-statement initial document data fetch with inline RBAC.
  # One SQL = one MVCC snapshot = no TOCTOU between snapshot and updates fetch.
  # Returns 0 rows if user lacks document:read, 1 row otherwise.
  @initial_document_data_sql """
  WITH authorized_document AS (
    SELECT d.id AS document_id, d.active_snapshot_id
    FROM documents d
    LEFT JOIN users u
      ON u.id = $3
    LEFT JOIN workspace_members wm
      ON wm.workspace_id = d.workspace_id AND wm.user_id = $3
    LEFT JOIN workspace_roles wr
      ON wr.id = wm.role_id
    LEFT JOIN workspace_role_permissions wrp
      ON wrp.role_id = wr.id AND wrp.permission = 'document:read'
    WHERE d.id = $1 AND d.workspace_id = $2
      AND CASE
            WHEN u.account_type = 'guest' THEN TRUE
            WHEN wm.user_id IS NULL THEN FALSE
            WHEN wr.base_role = 'owner' THEN TRUE
            WHEN wrp.granted IS NOT NULL THEN wrp.granted
            WHEN wr.catalog_version IS NOT NULL AND wr.catalog_version < 1 THEN FALSE
            ELSE TRUE
          END
  )
  SELECT
    s.id, s.document_id, s.parent_snapshot_id,
    s.latest_version, s.data, s.nonce, s.key_version,
    s.hybrid_signature, s.ciphertext_hash, s.snapshot_signature_hash,
    s.snapshot_admission_event_hash, s.proof_chain_hash, s.clocks,
    s.parent_snapshot_update_clocks, s.parent_proof_hash,
    s.created_by_signing_key_id, s.owner_kind, s.owner_id,
    s.authority_kind, s.authority_id, s.authority_context_key,
    s.authority_scope_id, s.authority_permission_version,
    s.key_checkpoint_sequence, s.key_checkpoint_hash, s.created_at,
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
        'clock', du.clock,
        'version', du.version,
        'signing_key_id', du.signing_key_id,
        'update_data', encode(du.update_data, 'base64'),
        'nonce', encode(du.nonce, 'base64'),
        'key_version', du.key_version,
        'update_hash', du.update_hash,
        'hybrid_signature', du.hybrid_signature,
        'owner_kind', du.owner_kind,
        'owner_id', du.owner_id,
        'authority_kind', du.authority_kind,
        'authority_id', du.authority_id,
        'authority_context_key', du.authority_context_key,
        'authority_scope_id', du.authority_scope_id,
        'authority_permission_version', du.authority_permission_version,
        'key_checkpoint_sequence', du.key_checkpoint_sequence,
        'key_checkpoint_hash', du.key_checkpoint_hash,
        'admission_event_hash', du.admission_event_hash,
        'write_session_counter', du.write_session_counter,
        'timestamp', du.timestamp
      ) ORDER BY du.version
    ) AS updates_json
    FROM document_updates du
    WHERE du.document_id = ad.document_id
      AND du.snapshot_id = ad.active_snapshot_id
      AND (
        NOT ($6::boolean AND s.id = $4)
        OR du.clock > COALESCE((($5::jsonb)->>(du.authority_context_key || ':' || du.signing_key_id))::integer, -1)
      )
  ) u ON TRUE
  """

  @spec get_initial_document_data(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, {DocumentSnapshot.t() | nil, [map()]}} | {:error, :unauthorized | :db_error}
  def get_initial_document_data(document_id, workspace_id, user_id, params \\ %{}) do
    update_filter = initial_update_filter(params)

    with :ok <- validate_guest_document_read(workspace_id, user_id, document_id),
         {:ok, %{rows: rows, columns: columns}} <-
           Repo.query(
             @initial_document_data_sql,
             [
               Ecto.UUID.dump!(document_id),
               Ecto.UUID.dump!(workspace_id),
               Ecto.UUID.dump!(user_id),
               update_filter.known_snapshot_id,
               update_filter.known_clocks,
               update_filter.delta_mode
             ]
           ) do
      case rows do
        [row] -> {:ok, parse_initial_data_row(row, columns)}
        [] -> {:error, :unauthorized}
      end
    else
      {:error, :permission_denied} ->
        {:error, :unauthorized}

      {:error, _reason} ->
        {:error, :db_error}
    end
  end

  defp validate_guest_document_read(workspace_id, user_id, document_id) do
    if Workspaces.guest_user?(user_id) do
      case get_document(document_id) do
        %Document{} = document ->
          Workspaces.authorize_guest_permission(workspace_id, user_id, "document:read", document)

        nil ->
          {:error, :permission_denied}
      end
    else
      :ok
    end
  end

  @initial_document_data_share_sql """
  WITH RECURSIVE selected_share AS (
    SELECT
      sh.id AS selected_share_id,
      sh.parent_share_id,
      sh.document_id AS selected_document_id,
      sh.scope AS selected_scope,
      sh.expires_event_sequence AS selected_expires_event_sequence,
      COALESCE(root_sh.id, sh.id) AS root_share_id,
      COALESCE(root_sh.document_id, sh.document_id) AS root_document_id,
      COALESCE(root_sh.scope, sh.scope) AS root_scope,
      COALESCE(root_sh.expires_event_sequence, sh.expires_event_sequence) AS root_expires_event_sequence
    FROM shares sh
    LEFT JOIN shares root_sh ON root_sh.id = sh.parent_share_id
    WHERE sh.id = $2
  ),
  share_descendants AS (
    SELECT child.id, child.parent_id
    FROM documents child
    JOIN selected_share ss ON TRUE
    WHERE child.parent_id = ss.root_document_id
    UNION ALL
    SELECT child.id, child.parent_id
    FROM documents child
    INNER JOIN share_descendants sd ON child.parent_id = sd.id
  )
  SELECT
    s.id, s.document_id, s.parent_snapshot_id,
    s.latest_version, s.data, s.nonce, s.key_version,
    s.hybrid_signature, s.ciphertext_hash, s.snapshot_signature_hash,
    s.snapshot_admission_event_hash, s.proof_chain_hash, s.clocks,
    s.parent_snapshot_update_clocks, s.parent_proof_hash,
    s.created_by_signing_key_id, s.owner_kind, s.owner_id,
    s.authority_kind, s.authority_id, s.authority_context_key,
    s.authority_scope_id, s.authority_permission_version,
    s.key_checkpoint_sequence, s.key_checkpoint_hash, s.created_at,
    COALESCE(u.updates_json, '[]'::jsonb) AS updates_json
  FROM selected_share ss
  JOIN documents d
    ON d.id = $1
  LEFT JOIN document_snapshots s
    ON s.id = d.active_snapshot_id AND s.document_id = d.id
  LEFT JOIN LATERAL (
    SELECT jsonb_agg(
      jsonb_build_object(
        'id', du.id,
        'document_id', du.document_id,
        'snapshot_id', du.snapshot_id,
        'clock', du.clock,
        'version', du.version,
        'signing_key_id', du.signing_key_id,
        'update_data', encode(du.update_data, 'base64'),
        'nonce', encode(du.nonce, 'base64'),
        'key_version', du.key_version,
        'update_hash', du.update_hash,
        'hybrid_signature', du.hybrid_signature,
        'owner_kind', du.owner_kind,
        'owner_id', du.owner_id,
        'authority_kind', du.authority_kind,
        'authority_id', du.authority_id,
        'authority_context_key', du.authority_context_key,
        'authority_scope_id', du.authority_scope_id,
        'authority_permission_version', du.authority_permission_version,
        'key_checkpoint_sequence', du.key_checkpoint_sequence,
        'key_checkpoint_hash', du.key_checkpoint_hash,
        'admission_event_hash', du.admission_event_hash,
        'write_session_counter', du.write_session_counter,
        'timestamp', du.timestamp
      ) ORDER BY du.version
    ) AS updates_json
    FROM document_updates du
    WHERE du.document_id = d.id
      AND du.snapshot_id = d.active_snapshot_id
      AND (
        NOT ($6::boolean AND s.id = $4)
        OR du.clock > COALESCE((($5::jsonb)->>(du.authority_context_key || ':' || du.signing_key_id))::integer, -1)
      )
  ) u ON TRUE
  WHERE d.id = $1
    AND ss.selected_expires_event_sequence > $3
    AND ss.root_expires_event_sequence > $3
    AND (
      (
        ss.parent_share_id IS NULL
        AND ss.selected_scope = 'document'
        AND ss.selected_document_id = d.id
      )
      OR (
        ss.root_scope = 'folder'
        AND (
          ss.parent_share_id IS NULL
          OR ss.selected_document_id = d.id
        )
        AND EXISTS(
          SELECT 1
          FROM shares child_sh
          WHERE child_sh.parent_share_id = ss.root_share_id
            AND child_sh.document_id = d.id
            AND child_sh.scope = 'document'
        )
        AND EXISTS(
          SELECT 1
          FROM share_descendants sd
          WHERE sd.id = d.id
        )
      )
    )
  """

  @spec get_initial_document_data_for_share(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, {DocumentSnapshot.t() | nil, [map()]}} | {:error, :unauthorized | :db_error}
  def get_initial_document_data_for_share(document_id, share_id, params \\ %{}) do
    update_filter = initial_update_filter(params)

    case current_workspace_event_sequence_for_document(document_id) do
      {:ok, current_sequence} ->
        case Repo.query(@initial_document_data_share_sql, [
               Ecto.UUID.dump!(document_id),
               Ecto.UUID.dump!(share_id),
               current_sequence,
               update_filter.known_snapshot_id,
               update_filter.known_clocks,
               update_filter.delta_mode
             ]) do
          {:ok, %{rows: [row], columns: columns}} ->
            {:ok, parse_initial_data_row(row, columns)}

          {:ok, %{rows: []}} ->
            {:error, :unauthorized}

          {:error, _} ->
            {:error, :db_error}
        end

      _ ->
        {:error, :db_error}
    end
  end

  defp initial_update_filter(%{
         "mode" => "delta",
         "knownSnapshotId" => known_snapshot_id,
         "knownSnapshotUpdateClocks" => known_clocks
       })
       when is_map(known_clocks) do
    case Ecto.UUID.dump(known_snapshot_id) do
      {:ok, dumped_snapshot_id} ->
        %{
          known_snapshot_id: dumped_snapshot_id,
          known_clocks: known_clocks,
          delta_mode: true
        }

      :error ->
        %{known_snapshot_id: nil, known_clocks: %{}, delta_mode: false}
    end
  end

  defp initial_update_filter(_params),
    do: %{known_snapshot_id: nil, known_clocks: %{}, delta_mode: false}

  defp current_workspace_event_sequence_for_document(document_id) do
    workspace_id =
      from(d in Document, where: d.id == ^document_id, select: d.workspace_id)
      |> Repo.one()

    case workspace_id && Encryption.current_workspace_key_directory_pin(workspace_id) do
      %{event_head_sequence: sequence} when is_integer(sequence) and sequence > 0 ->
        {:ok, sequence}

      _ ->
        :error
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
            latest_version: row_map["latest_version"],
            data: row_map["data"],
            nonce: row_map["nonce"],
            key_version: row_map["key_version"],
            hybrid_signature: row_map["hybrid_signature"],
            ciphertext_hash: row_map["ciphertext_hash"],
            snapshot_signature_hash: row_map["snapshot_signature_hash"],
            snapshot_admission_event_hash: row_map["snapshot_admission_event_hash"],
            proof_chain_hash: row_map["proof_chain_hash"],
            clocks: row_map["clocks"],
            parent_snapshot_update_clocks: row_map["parent_snapshot_update_clocks"],
            parent_proof_hash: row_map["parent_proof_hash"],
            created_by_signing_key_id: row_map["created_by_signing_key_id"],
            owner_kind: row_map["owner_kind"],
            owner_id: row_map["owner_id"],
            authority_kind: row_map["authority_kind"],
            authority_id: row_map["authority_id"],
            authority_context_key: row_map["authority_context_key"],
            authority_scope_id: row_map["authority_scope_id"],
            authority_permission_version: row_map["authority_permission_version"],
            key_checkpoint_sequence: row_map["key_checkpoint_sequence"],
            key_checkpoint_hash: row_map["key_checkpoint_hash"],
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
          clock: u["clock"],
          version: u["version"],
          signing_key_id: u["signing_key_id"],
          update_data: Base.decode64!(u["update_data"], ignore: :whitespace),
          nonce: Base.decode64!(u["nonce"], ignore: :whitespace),
          key_version: u["key_version"],
          update_hash: u["update_hash"],
          hybrid_signature: u["hybrid_signature"],
          owner_kind: u["owner_kind"],
          owner_id: u["owner_id"],
          authority_kind: u["authority_kind"],
          authority_id: u["authority_id"],
          authority_context_key: u["authority_context_key"],
          authority_scope_id: u["authority_scope_id"],
          authority_permission_version: u["authority_permission_version"],
          key_checkpoint_sequence: u["key_checkpoint_sequence"],
          key_checkpoint_hash: u["key_checkpoint_hash"],
          admission_event_hash: u["admission_event_hash"],
          write_session_counter: u["write_session_counter"],
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

  # ── Create ───────────────────────────────────────

  @spec create_document(map()) :: {:ok, Document.t()} | {:error, Ecto.Changeset.t()}
  def create_document(attrs) do
    encrypted_title = get_attr(attrs, :encrypted_title)
    title = get_attr(attrs, :title)
    workspace_id = get_attr(attrs, :workspace_id)
    parent_id = get_attr(attrs, :parent_id)

    is_encrypted = encrypted_title != nil
    position = Ordering.append_position(workspace_id, parent_id)
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
          {:ok, Document.t()}
          | {:error,
             Ecto.Changeset.t()
             | :document_archived
             | :document_read_only
             | :document_write_disabled}
  def update_document(%Document{} = document, attrs) do
    case writable_document?(document) do
      :ok ->
        changeset =
          document
          |> Document.changeset(attrs)
          |> validate_parent_constraints()
          |> validate_parent_change(document.id)

        update_document_result(document, changeset)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── Delete ───────────────────────────────────────

  @spec delete_document(Document.t()) ::
          {:ok, Document.t()} | {:error, Ecto.Changeset.t() | :folder_not_empty}
  def delete_document(%Document{} = document) do
    if document.doc_type == "folder" && has_children?(document.id) do
      {:error, :folder_not_empty}
    else
      document
      |> delete_document_result()
      |> normalize_delete_document_result(document.id)
    end
  end

  defp delete_document_tx(document) do
    public_deleted? = RefMD.Public.handle_document_deleted(document.id) == :published_deleted
    affected_groups = Ordering.affected_parent_groups_for_document(document.id)

    case Repo.delete(document) do
      {:ok, deleted} ->
        Ordering.normalize_combined_siblings!(document.workspace_id, document.parent_id)
        Ordering.normalize_combined_sibling_groups!(affected_groups)
        {deleted, public_deleted?}

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp delete_document_result(document),
    do: Repo.transaction(fn -> delete_document_tx(document) end)

  defp normalize_delete_document_result({:ok, {deleted, true}}, document_id) do
    RefMD.Public.broadcast_unpublished(document_id)
    {:ok, deleted}
  end

  defp normalize_delete_document_result({:ok, {deleted, false}}, _document_id), do: {:ok, deleted}
  defp normalize_delete_document_result({:error, reason}, _document_id), do: {:error, reason}

  defp update_document_result(document, changeset) do
    if Map.has_key?(changeset.changes, :parent_id) do
      document
      |> update_document_parent_result(changeset)
      |> normalize_update_document_result()
    else
      Repo.update(changeset)
    end
  end

  defp update_document_parent_result(document, changeset) do
    Repo.transaction(fn -> update_document_parent_tx(document, changeset) end)
  end

  defp update_document_parent_tx(document, changeset) do
    case Repo.update(changeset) do
      {:ok, updated} ->
        normalize_parent_change!(document, updated)
        Repo.get!(Document, updated.id)

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp normalize_update_document_result({:ok, updated}), do: {:ok, updated}
  defp normalize_update_document_result({:error, reason}), do: {:error, reason}

  defp normalize_parent_change!(%Document{} = original, %Document{} = updated) do
    if original.parent_id != updated.parent_id do
      Ordering.normalize_combined_siblings!(original.workspace_id, original.parent_id)
    end

    Ordering.normalize_combined_siblings!(updated.workspace_id, updated.parent_id)
  end

  # ── Write State ───────────────────────────────────

  @spec archive_document(Document.t(), map()) ::
          {:ok, Document.t()} | {:error, :already_archived | :invalid_key_directory}
  def archive_document(%Document{} = document, write_state_admission) do
    if document_write_state(document) == "archived" do
      {:error, :already_archived}
    else
      archive_document_with_admission(document, write_state_admission)
    end
  end

  @spec unarchive_document(Document.t(), map()) ::
          {:ok, Document.t()}
          | {:error, :not_archived | :ancestor_archived | :invalid_key_directory}
  def unarchive_document(%Document{} = document, write_state_admission) do
    cond do
      document_write_state(document) != "archived" ->
        {:error, :not_archived}

      has_archived_ancestor?(document.id) ->
        {:error, :ancestor_archived}

      true ->
        unarchive_document_with_admission(document, write_state_admission)
    end
  end

  @spec enable_document_read_only(Document.t(), map()) ::
          {:ok, Document.t()}
          | {:error,
             :already_read_only
             | :document_archived
             | :document_write_disabled
             | :invalid_key_directory
             | :invalid_write_state_transition}
  def enable_document_read_only(%Document{} = document, write_state_admission) do
    update_single_document_write_state(
      document,
      write_state_admission,
      "read_only",
      "read_only_enabled"
    )
  end

  @spec disable_document_read_only(Document.t(), map()) ::
          {:ok, Document.t()}
          | {:error,
             :not_read_only
             | :document_archived
             | :document_write_disabled
             | :invalid_key_directory
             | :invalid_write_state_transition}
  def disable_document_read_only(%Document{} = document, write_state_admission) do
    update_single_document_write_state(
      document,
      write_state_admission,
      "writable",
      "read_only_disabled"
    )
  end

  @spec disable_document_writes_by_policy(Document.t(), map()) ::
          {:ok, Document.t()}
          | {:error,
             :already_write_disabled
             | :document_archived
             | :invalid_key_directory
             | :invalid_write_state_transition}
  def disable_document_writes_by_policy(%Document{} = document, write_state_admission) do
    update_single_document_write_state(
      document,
      write_state_admission,
      "write_disabled",
      "policy"
    )
  end

  defp archive_document_with_admission(document, write_state_admission) do
    case Repo.transaction(
           fn ->
             now = DateTime.utc_now()
             affected = archive_write_state_changes(document.id)

             :ok =
               WriteStateAdmission.append!(
                 document,
                 write_state_admission,
                 affected,
                 "archive"
               )

             affected
             |> affected_document_ids()
             |> update_archived_documents(now)

             %{document | archived_at: now, write_state: "archived", updated_at: now}
           end,
           isolation: :serializable
         ) do
      {:ok, updated} -> {:ok, updated}
      {:error, :invalid_key_directory} -> {:error, :invalid_key_directory}
    end
  end

  defp unarchive_document_with_admission(document, write_state_admission) do
    case Repo.transaction(
           fn ->
             now = DateTime.utc_now()
             affected = unarchive_write_state_changes(document.id)

             :ok =
               WriteStateAdmission.append!(
                 document,
                 write_state_admission,
                 affected,
                 "unarchive"
               )

             affected
             |> affected_document_ids()
             |> update_unarchived_documents(now)

             %{document | archived_at: nil, write_state: "writable", updated_at: now}
           end,
           isolation: :serializable
         ) do
      {:ok, updated} -> {:ok, updated}
      {:error, :invalid_key_directory} -> {:error, :invalid_key_directory}
    end
  end

  defp update_single_document_write_state(document, write_state_admission, target_state, reason) do
    case Repo.transaction(
           fn ->
             update_single_document_write_state_tx(
               document,
               write_state_admission,
               target_state,
               reason
             )
           end,
           isolation: :serializable
         ) do
      {:ok, updated} -> {:ok, updated}
      {:error, reason} -> {:error, reason}
    end
  end

  defp update_single_document_write_state_tx(
         document,
         write_state_admission,
         target_state,
         reason
       ) do
    locked = lock_document_for_write_state!(document.id)
    previous_state = document_write_state(locked)

    case allowed_single_write_state_transition(previous_state, target_state, reason) do
      :ok ->
        append_single_write_state_admission!(
          locked,
          write_state_admission,
          previous_state,
          target_state,
          reason
        )

        persist_single_document_write_state!(locked, target_state)

      {:error, transition_reason} ->
        Repo.rollback(transition_reason)
    end
  end

  defp lock_document_for_write_state!(document_id) do
    Document
    |> where([d], d.id == ^document_id)
    |> lock("FOR UPDATE")
    |> Repo.one!()
  end

  defp append_single_write_state_admission!(
         document,
         write_state_admission,
         previous_state,
         target_state,
         reason
       ) do
    affected = [
      %{id: document.id, previous_write_state: previous_state, write_state: target_state}
    ]

    WriteStateAdmission.append!(document, write_state_admission, affected, reason)
  end

  defp persist_single_document_write_state!(document, target_state) do
    now = DateTime.utc_now()
    archived_at = if target_state == "archived", do: now, else: nil

    {1, nil} =
      Document
      |> where([d], d.id == ^document.id)
      |> Repo.update_all(
        set: [
          write_state: target_state,
          archived_at: archived_at,
          updated_at: now
        ]
      )

    %{document | write_state: target_state, archived_at: archived_at, updated_at: now}
  end

  defp allowed_single_write_state_transition("writable", "read_only", "read_only_enabled"),
    do: :ok

  defp allowed_single_write_state_transition("read_only", "writable", "read_only_disabled"),
    do: :ok

  defp allowed_single_write_state_transition(state, "write_disabled", "policy")
       when state in ["writable", "read_only"],
       do: :ok

  defp allowed_single_write_state_transition("read_only", "read_only", "read_only_enabled"),
    do: {:error, :already_read_only}

  defp allowed_single_write_state_transition("writable", "writable", "read_only_disabled"),
    do: {:error, :not_read_only}

  defp allowed_single_write_state_transition(
         "write_disabled",
         "write_disabled",
         "policy"
       ),
       do: {:error, :already_write_disabled}

  defp allowed_single_write_state_transition("archived", _target_state, _reason),
    do: {:error, :document_archived}

  defp allowed_single_write_state_transition("write_disabled", _target_state, _reason),
    do: {:error, :document_write_disabled}

  defp allowed_single_write_state_transition(_previous_state, _target_state, _reason),
    do: {:error, :invalid_write_state_transition}

  defp affected_document_ids(affected), do: Enum.map(affected, & &1.id)

  defp update_archived_documents(document_ids, now) do
    Document
    |> where([d], d.id in ^document_ids)
    |> Repo.update_all(set: [archived_at: now, write_state: "archived", updated_at: now])
  end

  defp update_unarchived_documents(document_ids, now) do
    Document
    |> where([d], d.id in ^document_ids)
    |> Repo.update_all(set: [archived_at: nil, write_state: "writable", updated_at: now])
  end

  defp archive_write_state_changes(document_id) do
    document_id
    |> descendant_archive_rows()
    |> Enum.reject(& &1.archived?)
    |> Enum.map(fn row ->
      %{id: row.id, previous_write_state: row.write_state, write_state: "archived"}
    end)
  end

  defp unarchive_write_state_changes(document_id) do
    document_id
    |> descendant_archive_rows()
    |> Enum.filter(& &1.archived?)
    |> Enum.map(fn row ->
      %{id: row.id, previous_write_state: "archived", write_state: "writable"}
    end)
  end

  defp descendant_archive_rows(document_id) do
    result =
      Repo.query!(
        """
        WITH RECURSIVE descendants AS (
          SELECT id, archived_at, write_state FROM documents WHERE id = $1
          UNION ALL
          SELECT d.id, d.archived_at, d.write_state FROM documents d
          INNER JOIN descendants ds ON d.parent_id = ds.id
        )
        SELECT
          id::text,
          archived_at IS NOT NULL OR write_state = 'archived',
          CASE
            WHEN archived_at IS NOT NULL THEN 'archived'
            ELSE COALESCE(write_state, 'writable')
          END
        FROM descendants
        """,
        [Ecto.UUID.dump!(document_id)]
      )

    Enum.map(result.rows, fn [id, archived?, write_state] ->
      %{id: id, archived?: archived?, write_state: write_state}
    end)
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
          WHERE d.archived_at IS NOT NULL OR d.write_state = 'archived'
        )
        """,
        [Ecto.UUID.dump!(document_id)]
      )

    result.rows |> hd() |> hd()
  end

  defp writable_document?(%Document{} = document) do
    case document_write_state(document) do
      "writable" -> :ok
      "archived" -> {:error, :document_archived}
      "read_only" -> {:error, :document_read_only}
      "write_disabled" -> {:error, :document_write_disabled}
    end
  end

  defp document_write_state(%Document{archived_at: %DateTime{}}), do: "archived"
  defp document_write_state(%Document{archived_at: %NaiveDateTime{}}), do: "archived"

  defp document_write_state(%Document{write_state: state})
       when state in ["writable", "read_only", "archived", "write_disabled"], do: state

  defp document_write_state(%Document{}), do: "writable"

  # ── Hierarchy Helpers (shared with Reordering) ──

  @doc false
  @spec depth_from_root(Ecto.UUID.t()) :: non_neg_integer()
  def depth_from_root(parent_id) do
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

  @doc false
  @spec subtree_depth(Ecto.UUID.t()) :: non_neg_integer()
  def subtree_depth(document_id) do
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
    if document_write_state(parent) == "archived" do
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
        new_position = Ordering.append_position(workspace_id, nil)
        force_change(changeset, :position, new_position)

      {:ok, new_parent_id} ->
        workspace_id = get_field(changeset, :workspace_id)
        new_position = Ordering.append_position(workspace_id, new_parent_id)

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
    document_children? =
      from(d in Document, where: d.parent_id == ^document_id, limit: 1)
      |> Repo.exists?()

    document_children? or Sharing.share_mount_children?(document_id)
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

  defp get_attr(attrs, key) when is_atom(key), do: dual_key_get(attrs, key)

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, val} -> val
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end
end
