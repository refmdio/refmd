defmodule RefMD.Encryption.Documents do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Repo
  alias RefMD.Sharing

  def create(attrs) do
    %DocumentEncryptedKey{created_at: DateTime.utc_now()}
    |> DocumentEncryptedKey.changeset(attrs)
    |> Repo.insert()
  end

  def get_active(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.is_active == true
    )
    |> Repo.one()
  end

  def list(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id,
      order_by: [asc: k.key_version]
    )
    |> Repo.all()
  end

  def rewrap_for_kek_rotation(document_id, key_version, new_kek_version, attrs) do
    Repo.transaction(fn ->
      key =
        from(k in DocumentEncryptedKey,
          join: d in RefMD.Documents.Document,
          on: d.id == k.document_id,
          join: w in RefMD.Workspaces.Workspace,
          on: w.id == d.workspace_id,
          where:
            k.document_id == ^document_id and k.key_version == ^key_version and
              w.needs_kek_rotation == true and
              w.current_kek_version + 1 == ^new_kek_version,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      if is_nil(key), do: Repo.rollback(:kek_rotation_rewrap_not_allowed)

      key
      |> DocumentEncryptedKey.changeset(%{
        encrypted_dek: attrs.encrypted_dek,
        nonce: attrs.nonce,
        kek_version: new_kek_version
      })
      |> Repo.update!()
    end)
    |> case do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, reason}
    end
  end

  def create_with_rotation(attrs), do: create_with_rotation(attrs, %{})

  def create_with_rotation(attrs, share_rotation) do
    document_id = dual_key_get(attrs, :document_id)
    key_version = dual_key_get(attrs, :key_version)
    kek_version = dual_key_get(attrs, :kek_version)

    Repo.transaction(fn ->
      document = lock_and_validate_document!(document_id, key_version)

      if RotationPolicy.dek_overdue?(document) and key_version <= document.min_dek_version,
        do: Repo.rollback(:dek_rotation_required)

      validate_kek_version!(document.workspace_id, kek_version)
      validate_consecutive_key_version!(document_id, key_version)
      maybe_append_dek_rotation_start!(document, key_version, share_rotation)
      maybe_rotate_share_keys!(document, key_version, share_rotation)
      insert_dek_with_rotation!(document, attrs, key_version)
    end)
  end

  defp maybe_append_dek_rotation_start!(document, key_version, attrs) do
    if key_version > document.min_dek_version do
      append_dek_rotation_start!(document, key_version, attrs)
    end
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp append_dek_rotation_start!(document, key_version, attrs) do
    events = Map.get(attrs, :dek_rotation_start_events)
    checkpoint = Map.get(attrs, :dek_rotation_start_checkpoint)

    with [%{"payload" => payload}] <- events,
         %{} <- checkpoint,
         true <- valid_dek_rotation_start?(payload, document, key_version) do
      RefMD.Encryption.append_workspace_key_directory!(
        document.workspace_id,
        events,
        checkpoint,
        checkpoint_signer_kind: "device"
      )

      :ok
    else
      _ -> Repo.rollback(:invalid_key_directory)
    end
  end

  defp valid_dek_rotation_start?(payload, document, key_version) do
    payload["event_type"] == "rotation_started" and
      get_in(payload, ["body", "rotation_kind"]) == "dek" and
      get_in(payload, ["body", "scope_kind"]) == "document" and
      get_in(payload, ["body", "scope_id"]) == document.id and
      get_in(payload, ["body", "old_key_version"]) == document.min_dek_version and
      get_in(payload, ["body", "new_key_version"]) == key_version and
      get_in(payload, ["body", "reason"]) == authoritative_dek_rotation_reason(document)
  end

  defp authoritative_dek_rotation_reason(%{dek_rotation_reason: reason})
       when is_binary(reason),
       do: reason

  defp authoritative_dek_rotation_reason(document) do
    if RotationPolicy.dek_overdue?(document), do: "time_based"
  end

  defp maybe_rotate_share_keys!(document, key_version, share_rotation) do
    if key_version > document.min_dek_version do
      Sharing.rotate_share_keys_for_dek!(document, key_version, share_rotation)
    end
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
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

    if RotationPolicy.kek_overdue?(workspace) do
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

    updates = [
      min_dek_version: key_version,
      dek_rotation_due_at: RotationPolicy.next_dek_due_at()
    ]

    updates =
      if is_rotation, do: Keyword.put(updates, :needs_rotation_snapshot, true), else: updates

    updates =
      if document.needs_dek_rotation do
        updates
        |> Keyword.put(:needs_dek_rotation, false)
        |> Keyword.put(:dek_rotation_reason, nil)
      else
        updates
      end

    from(d in RefMD.Documents.Document, where: d.id == ^document.id)
    |> Repo.update_all(set: updates)
  end
end
