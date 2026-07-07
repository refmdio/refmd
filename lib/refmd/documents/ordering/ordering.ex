defmodule RefMD.Documents.Ordering do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo

  @temp_position -2_147_483_648

  def count_combined_siblings(workspace_id, parent_id) do
    length(list_combined_siblings(workspace_id, parent_id, nil))
  end

  def append_position(workspace_id, parent_id) do
    workspace_id
    |> list_combined_sibling_rows(parent_id, nil)
    |> Enum.map(& &1.position)
    |> Enum.max(fn -> -1 end)
    |> Kernel.+(1)
  end

  def normalize_combined_siblings!(workspace_id, parent_id) do
    workspace_id
    |> list_combined_siblings(parent_id, nil)
    |> then(&normalize_combined_sibling_order!(workspace_id, parent_id, &1))
  end

  def normalize_combined_siblings_for_document!(document_id) do
    document_id
    |> affected_parent_groups_for_document()
    |> normalize_combined_sibling_groups!()

    :ok
  end

  def affected_parent_groups_for_document(document_id) do
    document_id
    |> affected_mount_parent_groups()
    |> Enum.concat(affected_share_parent_groups(document_id))
    |> Enum.uniq()
  end

  def normalize_combined_sibling_groups!(groups) do
    Enum.each(groups, fn {workspace_id, parent_id} ->
      normalize_combined_siblings!(workspace_id, parent_id)
    end)

    :ok
  end

  def move_document!(%Document{} = document, parent_id, position) do
    old_parent_id = document.parent_id
    set_document_parent_temp_position!(document.id, old_parent_id)

    if old_parent_id != parent_id do
      siblings =
        list_combined_siblings(document.workspace_id, old_parent_id, document_ref(document))

      normalize_combined_sibling_order!(document.workspace_id, old_parent_id, siblings)
    end

    set_document_parent_temp_position!(document.id, parent_id)

    new_siblings =
      list_combined_siblings(document.workspace_id, parent_id, document_ref(document))

    target_position = position |> max(0) |> min(length(new_siblings))
    ordered = List.insert_at(new_siblings, target_position, document_ref(document))

    normalize_combined_sibling_order!(document.workspace_id, parent_id, ordered)
  end

  def move_share_mount!(
        %{id: mount_id, workspace_id: workspace_id, parent_id: old_parent_id},
        parent_id,
        position
      ) do
    if old_parent_id != parent_id do
      siblings = list_combined_siblings(workspace_id, old_parent_id, mount_ref(mount_id))
      normalize_combined_sibling_order!(workspace_id, old_parent_id, siblings)
    end

    new_siblings = list_combined_siblings(workspace_id, parent_id, mount_ref(mount_id))
    target_position = position |> max(0) |> min(length(new_siblings))
    ordered = List.insert_at(new_siblings, target_position, mount_ref(mount_id))

    set_share_mount_parent_position!(mount_id, parent_id, target_position)

    normalize_combined_sibling_order!(workspace_id, parent_id, ordered)
  end

  defp normalize_combined_sibling_order!(workspace_id, parent_id, ordered_siblings) do
    temporarily_negate_document_positions!(workspace_id, parent_id)

    ordered_siblings
    |> Enum.with_index()
    |> Enum.each(fn {sibling, position} ->
      set_combined_sibling_position!(sibling, position)
    end)

    :ok
  end

  defp list_combined_siblings(workspace_id, parent_id, excluded) do
    workspace_id
    |> list_combined_sibling_rows(parent_id, excluded)
    |> Enum.map(&Map.take(&1, [:kind, :id]))
  end

  defp list_combined_sibling_rows(workspace_id, parent_id, excluded) do
    document_rows =
      Document
      |> where([d], d.workspace_id == ^workspace_id)
      |> maybe_filter_by_parent_id(parent_id)
      |> select([d], %{kind: "document", id: d.id, position: d.position})
      |> Repo.all()

    mount_rows = list_share_mount_sibling_rows(workspace_id, parent_id)

    (document_rows ++ mount_rows)
    |> Enum.reject(&excluded_sibling?(&1, excluded))
    |> Enum.sort_by(&{&1.position, &1.id})
  end

  defp affected_mount_parent_groups(document_id) do
    Repo.query!(
      """
      SELECT workspace_id, parent_id
      FROM share_mounts
      WHERE target_document_id = $1 OR parent_id = $1
      """,
      [Ecto.UUID.dump!(document_id)]
    )
    |> uuid_group_rows()
    |> Enum.map(fn
      {workspace_id, ^document_id} -> {workspace_id, nil}
      group -> group
    end)
  end

  defp affected_share_parent_groups(document_id) do
    Repo.query!(
      """
      SELECT m.workspace_id, m.parent_id
      FROM share_mounts AS m
      INNER JOIN shares AS s ON s.id = m.share_id
      WHERE s.document_id = $1
      """,
      [Ecto.UUID.dump!(document_id)]
    )
    |> uuid_group_rows()
  end

  defp set_document_parent_temp_position!(document_id, parent_id) do
    parent_value = if parent_id, do: Ecto.UUID.dump!(parent_id)

    Repo.query!(
      "UPDATE documents SET parent_id = $1, position = $2, updated_at = $3 WHERE id = $4",
      [parent_value, @temp_position, DateTime.utc_now(), Ecto.UUID.dump!(document_id)]
    )
  end

  defp temporarily_negate_document_positions!(workspace_id, parent_id) do
    {clause, params} = combined_parent_id_sql(parent_id, 3)

    Repo.query!(
      "UPDATE documents SET position = -(position + 1), updated_at = $1 " <>
        "WHERE workspace_id = $2 AND #{clause} AND position >= 0",
      [DateTime.utc_now(), Ecto.UUID.dump!(workspace_id) | params]
    )
  end

  defp set_combined_sibling_position!(%{kind: "document", id: id}, position) do
    from(d in Document, where: d.id == ^id)
    |> Repo.update_all(set: [position: position, updated_at: DateTime.utc_now()])
  end

  defp set_combined_sibling_position!(%{kind: "mount", id: id}, position) do
    set_share_mount_position!(id, position)
  end

  defp list_share_mount_sibling_rows(workspace_id, parent_id) do
    {clause, params} = combined_parent_id_sql(parent_id, 2)

    Repo.query!(
      """
      SELECT id, position
      FROM share_mounts
      WHERE workspace_id = $1 AND #{clause}
      """,
      [Ecto.UUID.dump!(workspace_id) | params]
    )
    |> then(fn %{rows: rows} ->
      Enum.map(rows, fn [id, position] ->
        %{kind: "mount", id: database_uuid_to_string(id), position: position}
      end)
    end)
  end

  defp set_share_mount_parent_position!(mount_id, parent_id, position) do
    parent_value = if parent_id, do: Ecto.UUID.dump!(parent_id)

    Repo.query!(
      "UPDATE share_mounts SET parent_id = $1, position = $2 WHERE id = $3",
      [parent_value, position, Ecto.UUID.dump!(mount_id)]
    )
  end

  defp set_share_mount_position!(mount_id, position) do
    Repo.query!(
      "UPDATE share_mounts SET position = $1 WHERE id = $2",
      [position, Ecto.UUID.dump!(mount_id)]
    )
  end

  defp combined_parent_id_sql(nil, _start_param), do: {"parent_id IS NULL", []}

  defp combined_parent_id_sql(parent_id, start_param) do
    {"parent_id = $#{start_param}", [Ecto.UUID.dump!(parent_id)]}
  end

  defp maybe_filter_by_parent_id(query, nil), do: where(query, [row], is_nil(row.parent_id))

  defp maybe_filter_by_parent_id(query, parent_id),
    do: where(query, [row], row.parent_id == ^parent_id)

  defp document_ref(%Document{id: id}), do: %{kind: "document", id: id}
  defp mount_ref(id) when is_binary(id), do: %{kind: "mount", id: id}

  defp uuid_group_rows(%{rows: rows}) do
    Enum.map(rows, fn [workspace_id, parent_id] ->
      {database_uuid_to_string(workspace_id), database_uuid_to_string(parent_id)}
    end)
  end

  defp database_uuid_to_string(nil), do: nil

  defp database_uuid_to_string(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} ->
        uuid

      :error ->
        {:ok, uuid} = Ecto.UUID.load(value)
        uuid
    end
  end

  defp excluded_sibling?(_sibling, nil), do: false

  defp excluded_sibling?(sibling, excluded) do
    sibling.kind == excluded.kind and sibling.id == excluded.id
  end
end
