defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.{Changeset, Query}

  alias RefMD.Documents.{Document, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Repo

  @max_nesting_depth 10

  # ── Snapshots (delegated to RefMD.Documents.Snapshots) ──

  defdelegate save_update(document_id, user_id, attrs), to: RefMD.Documents.Snapshots
  defdelegate save_snapshot(document_id, user_id, attrs), to: RefMD.Documents.Snapshots

  defdelegate build_snapshot_proof_chain(document_id, pinned_snapshot_id, active_snapshot_id),
    to: RefMD.Documents.Snapshots

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
