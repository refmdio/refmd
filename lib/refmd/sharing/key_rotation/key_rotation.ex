defmodule RefMD.Sharing.KeyRotation do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Sharing.Management.KeyDirectory
  alias RefMD.Sharing.Shares.LinkSecretBackupWraps

  alias RefMD.Sharing.{
    Access,
    Share,
    ShareKey,
    ShareKeyHistory,
    ShareLinkSecretBackupWrap
  }

  def list_targets(%Document{} = document, user_id) do
    document.id
    |> current_target_rows(document.min_dek_version)
    |> Enum.reject(&Access.expired?(&1.root_share))
    |> attach_backup_wraps(user_id, document.workspace_id)
    |> Enum.map(&format_target/1)
  end

  def rotate_for_dek!(%Document{} = document, next_key_version, attrs) do
    targets =
      document.id
      |> locked_current_target_rows(document.min_dek_version)
      |> Enum.reject(&Access.expired?(&1.root_share))

    replacements = Map.get(attrs, :share_key_replacements, [])

    if targets == [] and replacements == [] do
      :ok
    else
      validated = validate_exact_replacements!(targets, replacements, next_key_version)
      event_hashes = KeyDirectory.append_rotation!(document.workspace_id, attrs, validated)
      update_latest_event_hashes!(targets, event_hashes)
      Enum.each(validated, &rotate_target!/1)
    end
  end

  def delete_obsolete_wraps!(document_id, current_key_version) do
    stale_rows = stale_target_rows(document_id, current_key_version)
    {expired_rows, active_rows} = Enum.split_with(stale_rows, &Access.expired?(&1.root_share))

    if active_rows != [] do
      Repo.rollback(:incomplete_share_key_rotation)
    end

    expired_share_ids = Enum.map(expired_rows, & &1.share_key.share_id)

    from(sk in ShareKey,
      where: sk.document_id == ^document_id,
      where: sk.share_id in ^expired_share_ids,
      where: sk.key_version < ^current_key_version
    )
    |> Repo.delete_all()

    from(h in ShareKeyHistory,
      where: h.document_id == ^document_id and h.key_version < ^current_key_version
    )
    |> Repo.delete_all()
  end

  defp current_target_rows(document_id, key_version) do
    target_query(document_id, key_version)
    |> Repo.all()
  end

  defp locked_current_target_rows(document_id, key_version) do
    document_id
    |> target_query(key_version)
    |> lock("FOR UPDATE")
    |> Repo.all()
  end

  defp stale_target_rows(document_id, current_key_version) do
    from(sk in ShareKey,
      join: target_share in Share,
      on: target_share.id == sk.share_id,
      join: root_share in Share,
      on:
        root_share.id == fragment("COALESCE(?, ?)", target_share.parent_share_id, target_share.id),
      where: sk.document_id == ^document_id and sk.key_version < ^current_key_version,
      lock: "FOR UPDATE",
      select: %{share_key: sk, root_share: root_share}
    )
    |> Repo.all()
  end

  defp target_query(document_id, key_version) do
    from(sk in ShareKey,
      join: target_share in Share,
      on: target_share.id == sk.share_id,
      join: root_share in Share,
      on:
        root_share.id == fragment("COALESCE(?, ?)", target_share.parent_share_id, target_share.id),
      where: sk.document_id == ^document_id and sk.key_version == ^key_version,
      select: %{share_key: sk, target_share: target_share, root_share: root_share}
    )
  end

  defp attach_backup_wraps(rows, user_id, workspace_id) do
    root_share_ids = rows |> Enum.map(& &1.root_share.id) |> Enum.uniq()

    wraps =
      from(w in ShareLinkSecretBackupWrap,
        where: w.share_id in ^root_share_ids and w.recipient_user_id == ^user_id,
        select: {w.share_id, w.wrap}
      )
      |> Repo.all()
      |> Enum.group_by(fn {share_id, _wrap} -> share_id end, fn {_share_id, wrap} ->
        LinkSecretBackupWraps.with_key_directory_proof(wrap, workspace_id)
      end)

    Enum.map(rows, &Map.put(&1, :backup_wraps, Map.get(wraps, &1.root_share.id, [])))
  end

  defp format_target(row) do
    %{
      root_share_id: row.root_share.id,
      root_document_id: row.root_share.document_id,
      target_share_id: row.target_share.id,
      document_id: row.share_key.document_id,
      current_key_version: row.share_key.key_version,
      permission: row.root_share.permission,
      password_protected: row.root_share.password_protected,
      max_views: row.root_share.max_views,
      expires_event_sequence: row.root_share.expires_event_sequence,
      share_link_secret_backup_wraps: row.backup_wraps
    }
  end

  defp validate_exact_replacements!(targets, replacements, next_key_version) do
    expected_by_share = Map.new(targets, &{&1.share_key.share_id, &1})

    validated =
      Enum.map(replacements, fn replacement ->
        share_id = Map.get(replacement, :share_id)
        target = Map.get(expected_by_share, share_id)

        if is_nil(target) or Map.get(replacement, :document_id) != target.share_key.document_id or
             Map.get(replacement, :root_share_id) != target.root_share.id or
             Map.get(replacement, :key_version) != next_key_version or
             not valid_ciphertext?(Map.get(replacement, :encrypted_dek)) or
             not valid_nonce?(Map.get(replacement, :nonce)) do
          Repo.rollback(:invalid_share_key_rotation)
        end

        Map.merge(replacement, %{target: target})
      end)

    provided_ids = validated |> Enum.map(& &1.share_id) |> MapSet.new()
    expected_ids = expected_by_share |> Map.keys() |> MapSet.new()

    if provided_ids != expected_ids or MapSet.size(provided_ids) != length(validated) do
      Repo.rollback(:incomplete_share_key_rotation)
    end

    validated
  end

  defp valid_ciphertext?(value), do: is_binary(value) and byte_size(value) == 48
  defp valid_nonce?(value), do: is_binary(value) and byte_size(value) == 24

  defp update_latest_event_hashes!(targets, event_hashes) do
    targets
    |> Enum.map(& &1.root_share)
    |> Enum.uniq_by(& &1.id)
    |> Enum.each(fn root_share ->
      event_hash = Map.fetch!(event_hashes, root_share.id)

      root_share
      |> Share.update_settings_changeset(%{latest_bootstrap_event_hash: event_hash})
      |> Repo.update!()
    end)
  end

  defp rotate_target!(%{target: %{share_key: share_key}} = replacement) do
    %ShareKeyHistory{}
    |> ShareKeyHistory.changeset(%{
      share_id: share_key.share_id,
      document_id: share_key.document_id,
      key_version: share_key.key_version,
      encrypted_dek: share_key.encrypted_dek,
      nonce: share_key.nonce
    })
    |> Repo.insert!()

    share_key
    |> ShareKey.changeset(%{
      key_version: replacement.key_version,
      encrypted_dek: replacement.encrypted_dek,
      nonce: replacement.nonce
    })
    |> Repo.update!()
  end
end
