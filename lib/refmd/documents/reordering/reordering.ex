defmodule RefMD.Documents.Reordering do
  @moduledoc false

  alias RefMD.Documents.{Document, Ordering}
  alias RefMD.Repo

  @max_nesting_depth 10

  def reorder_document(workspace_id, document_id, new_parent_id, new_position) do
    Repo.transaction(fn ->
      document = Repo.get(Document, document_id)

      validate_reorder_preconditions!(document, workspace_id)
      validate_reorder_parent!(new_parent_id, workspace_id)
      validate_reorder_hierarchy!(document, new_parent_id)

      Ordering.move_document!(document, new_parent_id, new_position)

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
end
