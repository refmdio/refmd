defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.{Changeset, Query}
  alias RefMD.Documents.Document
  alias RefMD.Repo

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
    document
    |> Document.changeset(attrs)
    |> validate_parent_constraints()
    |> validate_parent_change(document.id)
    |> Repo.update()
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
      target = min(new_position, max_pos)

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
