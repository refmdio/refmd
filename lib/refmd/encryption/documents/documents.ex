defmodule RefMD.Encryption.Documents do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Repo

  @spec create(map()) :: {:ok, DocumentEncryptedKey.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %DocumentEncryptedKey{created_at: DateTime.utc_now()}
    |> DocumentEncryptedKey.changeset(attrs)
    |> Repo.insert()
  end

  @spec get_active(Ecto.UUID.t()) :: DocumentEncryptedKey.t() | nil
  def get_active(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.is_active == true
    )
    |> Repo.one()
  end

  @spec list(Ecto.UUID.t()) :: [DocumentEncryptedKey.t()]
  def list(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id,
      order_by: [asc: k.key_version]
    )
    |> Repo.all()
  end

  @spec create_with_rotation(map()) :: {:ok, DocumentEncryptedKey.t()} | {:error, term()}
  def create_with_rotation(attrs) do
    document_id = attrs[:document_id] || attrs["document_id"]
    key_version = attrs[:key_version] || attrs["key_version"]
    kek_version = attrs[:kek_version] || attrs["kek_version"]

    Repo.transaction(fn ->
      document = lock_and_validate_document!(document_id, key_version)
      validate_kek_version!(document.workspace_id, kek_version)
      validate_consecutive_key_version!(document_id, key_version)
      insert_dek_with_rotation!(document, attrs, key_version)
    end)
  end

  defp validate_consecutive_key_version!(document_id, key_version) do
    max_version =
      from(k in DocumentEncryptedKey,
        where: k.document_id == ^document_id,
        select: max(k.key_version)
      )
      |> Repo.one()

    expected = (max_version || 0) + 1

    cond do
      key_version == expected -> :ok
      key_version <= (max_version || 0) -> :ok
      true -> Repo.rollback(:key_version_not_consecutive)
    end
  end

  defp lock_and_validate_document!(document_id, key_version) do
    document =
      from(d in RefMD.Documents.Document,
        where: d.id == ^document_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    if is_nil(document), do: Repo.rollback(:document_not_found)
    if key_version < document.min_dek_version, do: Repo.rollback(:key_version_too_old)

    document
  end

  defp validate_kek_version!(workspace_id, kek_version) do
    workspace =
      from(w in RefMD.Workspaces.Workspace,
        where: w.id == ^workspace_id,
        lock: "FOR SHARE"
      )
      |> Repo.one!()

    if workspace.needs_kek_rotation do
      Repo.rollback(:kek_rotation_required)
    end

    if kek_version != workspace.current_kek_version do
      Repo.rollback(:kek_version_mismatch)
    end
  end

  defp insert_dek_with_rotation!(document, attrs, key_version) do
    insert_attrs = Map.put(attrs, :is_active, true)

    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document.id and k.is_active == true
    )
    |> Repo.update_all(set: [is_active: false])

    case create(insert_attrs) do
      {:ok, key} ->
        update_document_after_dek_save(document, key_version)
        key

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp update_document_after_dek_save(document, key_version) do
    is_rotation = key_version > 1
    updates = [min_dek_version: key_version]

    updates =
      if is_rotation, do: Keyword.put(updates, :needs_rotation_snapshot, true), else: updates

    updates =
      if document.needs_dek_rotation do
        Keyword.put(updates, :needs_dek_rotation, false)
      else
        updates
      end

    from(d in RefMD.Documents.Document, where: d.id == ^document.id)
    |> Repo.update_all(set: updates)
  end
end
