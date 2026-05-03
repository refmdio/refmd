defmodule RefMD.Documents.TreeOrdering do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Sharing.ShareMount

  @temp_position -2_147_483_648

  @spec count_combined_siblings(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: non_neg_integer()
  def count_combined_siblings(workspace_id, parent_id) do
    length(list_combined_siblings(workspace_id, parent_id, nil))
  end

  @spec append_position(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: non_neg_integer()
  def append_position(workspace_id, parent_id) do
    workspace_id
    |> list_combined_sibling_rows(parent_id, nil)
    |> Enum.map(& &1.position)
    |> Enum.max(fn -> -1 end)
    |> Kernel.+(1)
  end

  @spec normalize_combined_siblings!(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: :ok
  def normalize_combined_siblings!(workspace_id, parent_id) do
    workspace_id
    |> list_combined_siblings(parent_id, nil)
    |> then(&normalize_combined_sibling_order!(workspace_id, parent_id, &1))
  end

  @spec normalize_combined_siblings_for_document!(Ecto.UUID.t()) :: :ok
  def normalize_combined_siblings_for_document!(document_id) do
    document_id
    |> affected_parent_groups_for_document()
    |> normalize_combined_sibling_groups!()

    :ok
  end

  @spec affected_parent_groups_for_document(Ecto.UUID.t()) :: [
          {Ecto.UUID.t(), Ecto.UUID.t() | nil}
        ]
  def affected_parent_groups_for_document(document_id) do
    document_id
    |> affected_mount_parent_groups()
    |> Enum.concat(affected_share_parent_groups(document_id))
    |> Enum.uniq()
  end

  @spec normalize_combined_sibling_groups!([{Ecto.UUID.t(), Ecto.UUID.t() | nil}]) :: :ok
  def normalize_combined_sibling_groups!(groups) do
    Enum.each(groups, fn {workspace_id, parent_id} ->
      normalize_combined_siblings!(workspace_id, parent_id)
    end)

    :ok
  end

  @spec move_document!(Document.t(), Ecto.UUID.t() | nil, non_neg_integer()) :: :ok
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

  @spec move_share_mount!(ShareMount.t(), Ecto.UUID.t() | nil, non_neg_integer()) :: :ok
  def move_share_mount!(%ShareMount{} = mount, parent_id, position) do
    old_parent_id = mount.parent_id

    if old_parent_id != parent_id do
      siblings = list_combined_siblings(mount.workspace_id, old_parent_id, mount_ref(mount))
      normalize_combined_sibling_order!(mount.workspace_id, old_parent_id, siblings)
    end

    new_siblings = list_combined_siblings(mount.workspace_id, parent_id, mount_ref(mount))
    target_position = position |> max(0) |> min(length(new_siblings))
    ordered = List.insert_at(new_siblings, target_position, mount_ref(mount))

    mount
    |> ShareMount.position_changeset(%{parent_id: parent_id, position: target_position})
    |> Repo.update!()

    normalize_combined_sibling_order!(mount.workspace_id, parent_id, ordered)
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

    mount_rows =
      ShareMount
      |> where([m], m.workspace_id == ^workspace_id)
      |> maybe_filter_by_parent_id(parent_id)
      |> select([m], %{kind: "mount", id: m.id, position: m.position})
      |> Repo.all()

    (document_rows ++ mount_rows)
    |> Enum.reject(&excluded_sibling?(&1, excluded))
    |> Enum.sort_by(&{&1.position, &1.id})
  end

  defp affected_mount_parent_groups(document_id) do
    from(m in ShareMount,
      where: m.target_document_id == ^document_id or m.parent_id == ^document_id,
      select: {m.workspace_id, m.parent_id}
    )
    |> Repo.all()
    |> Enum.map(fn
      {workspace_id, ^document_id} -> {workspace_id, nil}
      group -> group
    end)
  end

  defp affected_share_parent_groups(document_id) do
    from(m in ShareMount,
      join: s in assoc(m, :share),
      where: s.document_id == ^document_id,
      select: {m.workspace_id, m.parent_id}
    )
    |> Repo.all()
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
    from(m in ShareMount, where: m.id == ^id)
    |> Repo.update_all(set: [position: position])
  end

  defp combined_parent_id_sql(nil, _start_param), do: {"parent_id IS NULL", []}

  defp combined_parent_id_sql(parent_id, start_param) do
    {"parent_id = $#{start_param}", [Ecto.UUID.dump!(parent_id)]}
  end

  defp maybe_filter_by_parent_id(query, nil), do: where(query, [row], is_nil(row.parent_id))

  defp maybe_filter_by_parent_id(query, parent_id),
    do: where(query, [row], row.parent_id == ^parent_id)

  defp document_ref(%Document{id: id}), do: %{kind: "document", id: id}
  defp mount_ref(%ShareMount{id: id}), do: %{kind: "mount", id: id}

  defp excluded_sibling?(_sibling, nil), do: false

  defp excluded_sibling?(sibling, excluded) do
    sibling.kind == excluded.kind and sibling.id == excluded.id
  end
end
