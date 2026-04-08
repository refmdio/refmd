defmodule RefMD.Documents.Reordering do
  @moduledoc false

  alias RefMD.Documents.Document
  alias RefMD.Repo

  @max_nesting_depth 10
  @temp_position -2_147_483_648

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

    parent_depth = RefMD.Documents.depth_from_root(new_parent_id)
    sub_depth = RefMD.Documents.subtree_depth(document.id)

    if parent_depth + sub_depth > @max_nesting_depth do
      Repo.rollback(:nesting_too_deep)
    end
  end

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
end
