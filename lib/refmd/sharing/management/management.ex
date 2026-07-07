defmodule RefMD.Sharing.Management do
  @moduledoc """
  Owner and admin share management operations.
  """

  import Ecto.Query

  alias RefMD.Documents
  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Sharing.Management.KeyDirectory

  alias RefMD.Sharing.{
    Access,
    Share,
    ShareExclusion,
    ShareKey,
    ShareLinkSecretBackupWrap,
    ShareParticipantSession,
    Shares
  }

  def list_document_shares(%Document{} = document, actor_user_id, role) do
    base_query =
      from(s in Share,
        where: s.document_id == ^document.id and is_nil(s.parent_share_id),
        order_by: [desc: s.created_at]
      )

    query =
      case role.base_role do
        role when role in ["owner", "admin"] -> base_query
        _ -> from(s in base_query, where: s.created_by == ^actor_user_id)
      end

    shares =
      from(s in query,
        select: %{
          id: s.id,
          scope: s.scope,
          permission: s.permission,
          password_protected: s.password_protected,
          token_prefix: s.token_prefix,
          max_views: s.max_views,
          view_count: s.view_count,
          expires_event_sequence: s.expires_event_sequence,
          created_at: s.created_at
        }
      )
      |> Repo.all()

    shares
    |> attach_share_link_secret_backup_wraps(actor_user_id)
    |> attach_share_management_metadata()
  end

  defp attach_share_link_secret_backup_wraps(shares, user_id) do
    share_ids = Enum.map(shares, & &1.id)

    wraps =
      from(w in ShareLinkSecretBackupWrap,
        where: w.share_id in ^share_ids and w.recipient_user_id == ^user_id,
        select: {w.share_id, w.wrap}
      )
      |> Repo.all()
      |> Enum.group_by(fn {share_id, _wrap} -> share_id end, fn {_share_id, wrap} -> wrap end)

    Enum.map(shares, fn share ->
      Map.put(share, :share_link_secret_backup_wraps, Map.get(wraps, share.id, []))
    end)
  end

  def update_share_settings(document_id, share_id, attrs)
      when is_binary(document_id) and is_binary(share_id) and is_map(attrs) do
    with {:ok, update_attrs} <- parse_share_update_attrs(attrs),
         {:ok, key_directory} <- KeyDirectory.parse_append(attrs) do
      Repo.transaction(fn ->
        update_share_settings_tx(document_id, share_id, update_attrs, key_directory)
      end)
      |> normalize_share_settings_result()
    end
  end

  def delete_share(document_id, share_id, attrs \\ %{})

  def delete_share(document_id, share_id, attrs)
      when is_binary(document_id) and is_binary(share_id) do
    with {:ok, key_directory} <- KeyDirectory.parse_append(attrs) do
      Repo.transaction(fn ->
        document_id
        |> fetch_share_for_document!(share_id)
        |> delete_share_tx(key_directory)
      end)
      |> normalize_delete_result()
    end
  end

  def update_share_exclusions(document_id, share_id, attrs)
      when is_binary(document_id) and is_binary(share_id) and is_map(attrs) do
    with {:ok, update_attrs} <- parse_share_exclusion_update_attrs(attrs),
         {:ok, key_directory} <- KeyDirectory.parse_append(attrs) do
      Repo.transaction(fn ->
        update_share_exclusions_tx(document_id, share_id, update_attrs, key_directory)
      end)
      |> normalize_exclusion_update_result()
    end
  end

  def update_share_keys(document_id, share_id, attrs) do
    with {:ok, update_attrs} <- parse_share_key_update_attrs(attrs),
         {:ok, key_directory} <- key_directory_for_share_key_update(attrs, update_attrs) do
      Repo.transaction(fn ->
        update_share_keys_tx(document_id, share_id, update_attrs, key_directory)
      end)
      |> normalize_key_update_result()
    end
  end

  defp key_directory_for_share_key_update(_attrs, %{add_keys: [], replace_keys: []}),
    do: {:ok, :skip_key_directory}

  defp key_directory_for_share_key_update(attrs, _update_attrs),
    do: KeyDirectory.parse_append(attrs)

  defp attach_share_management_metadata([]), do: []

  defp attach_share_management_metadata(shares) do
    share_ids = Enum.map(shares, & &1.id)
    root_keys = root_share_management_keys(share_ids)
    child_shares = child_share_management_entries(share_ids)
    exclusions = share_management_exclusions(share_ids)

    Enum.map(shares, fn share ->
      root_key = Map.get(root_keys, share.id, %{})

      share
      |> Map.put(:salt, encode_nullable_base64url(root_key[:salt]))
      |> maybe_put_kdf_params(root_key[:kdf_params])
      |> Map.put(:child_shares, Map.get(child_shares, share.id, []))
      |> Map.put(:exclusions, Map.get(exclusions, share.id, []))
    end)
  end

  defp maybe_put_kdf_params(share, nil), do: share
  defp maybe_put_kdf_params(share, kdf_params), do: Map.put(share, :kdf_params, kdf_params)

  defp root_share_management_keys(share_ids) do
    from(sk in ShareKey,
      where: sk.share_id in ^share_ids,
      select: {sk.share_id, %{salt: sk.salt, kdf_params: sk.kdf_params}}
    )
    |> Repo.all()
    |> Map.new()
  end

  defp child_share_management_entries(share_ids) do
    from(s in Share,
      where: s.parent_share_id in ^share_ids,
      select: {s.parent_share_id, %{share_id: s.id, document_id: s.document_id}}
    )
    |> Repo.all()
    |> Enum.group_by(fn {parent_share_id, _entry} -> parent_share_id end, fn {_parent_share_id,
                                                                              entry} ->
      entry
    end)
  end

  defp share_management_exclusions(share_ids) do
    from(e in ShareExclusion,
      where: e.share_id in ^share_ids,
      select: {e.share_id, e.document_id}
    )
    |> Repo.all()
    |> Enum.group_by(fn {share_id, _document_id} -> share_id end, fn {_share_id, document_id} ->
      document_id
    end)
  end

  defp encode_nullable_base64url(nil), do: nil
  defp encode_nullable_base64url(value), do: Base.url_encode64(value, padding: false)

  defp update_share_settings_tx(document_id, share_id, update_attrs, key_directory) do
    {share, _share_key} = fetch_manageable_share!(document_id, share_id)

    signed_body =
      KeyDirectory.append_management!(share, key_directory, "share_metadata_updated")

    signed_update_attrs =
      KeyDirectory.signed_share_settings_update_attrs!(signed_body, update_attrs)
      |> Map.put(:permission_version, share.permission_version + 1)
      |> Map.put(
        :latest_bootstrap_event_hash,
        KeyDirectory.latest_event_hash!(key_directory, "share_metadata_updated")
      )

    share
    |> Share.update_settings_changeset(signed_update_attrs)
    |> Repo.update()
    |> build_share_settings_update_result()
  end

  defp build_share_settings_update_result({:ok, updated_share}) do
    %{
      share: updated_share,
      revoked_targets: settings_revocation_targets(updated_share)
    }
  end

  defp build_share_settings_update_result({:error, changeset}), do: Repo.rollback(changeset)

  defp settings_revocation_targets(updated_share) do
    if share_invalid_after_settings_update?(updated_share) do
      revoke_share_participant_sessions(updated_share.id)
    else
      []
    end
  end

  defp delete_share_tx(share, key_directory) do
    KeyDirectory.append_management!(share, key_directory, "share_revoked")
    revoked_targets = share_revocation_targets(share.id)
    affected_groups = Documents.affected_parent_groups_for_document(share.document_id)

    case Repo.delete(share) do
      {:ok, _deleted_share} ->
        Documents.normalize_combined_sibling_groups!(affected_groups)
        %{share_id: share.id, revoked_targets: revoked_targets}

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp update_share_exclusions_tx(document_id, share_id, update_attrs, key_directory) do
    {share, _share_key} = fetch_manageable_share!(document_id, share_id)

    KeyDirectory.append_management!(
      share,
      key_directory,
      "share_exclusion_changed",
      update_attrs
    )

    update_latest_bootstrap_event_hash!(
      share,
      KeyDirectory.latest_event_hash!(key_directory, "share_exclusion_changed")
    )

    case build_share_exclusion_update(share, update_attrs) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp build_share_exclusion_update(share, update_attrs) do
    with :ok <- validate_root_folder_share(share),
         {:ok, descendant_documents} <- list_folder_descendant_documents(share.document_id),
         :ok <-
           validate_exclusion_targets(
             update_attrs.add ++ update_attrs.remove,
             descendant_documents
           ) do
      apply_share_exclusion_update(share, update_attrs, descendant_documents)
    end
  end

  defp apply_share_exclusion_update(share, update_attrs, descendant_documents) do
    expanded_added_ids = expand_excluded_document_ids(update_attrs.add, descendant_documents)

    deleted_child_share_count = delete_folder_child_shares!(share.id, expanded_added_ids)
    insert_share_exclusions!(share.id, update_attrs.add)
    delete_share_exclusions!(share.id, update_attrs.remove)

    {:ok,
     %{
       share_id: share.id,
       exclusions: list_share_exclusion_ids(share.id),
       revoked_document_ids:
         revoked_exclusion_document_ids(deleted_child_share_count, expanded_added_ids)
     }}
  end

  defp revoked_exclusion_document_ids(deleted_child_share_count, expanded_added_ids)
       when deleted_child_share_count > 0,
       do: MapSet.to_list(expanded_added_ids)

  defp revoked_exclusion_document_ids(_deleted_child_share_count, _expanded_added_ids), do: []

  defp list_folder_descendant_documents(folder_id) do
    sql = """
    WITH RECURSIVE descendants AS (
      SELECT id, parent_id, doc_type
      FROM documents
      WHERE parent_id = $1 AND archived_at IS NULL
      UNION ALL
      SELECT d.id, d.parent_id, d.doc_type
      FROM documents d
      INNER JOIN descendants ds ON d.parent_id = ds.id
      WHERE d.archived_at IS NULL
    )
    SELECT id
    FROM descendants
    """

    case Repo.query(sql, [Ecto.UUID.dump!(folder_id)]) do
      {:ok, %{rows: rows}} -> {:ok, load_descendant_documents(rows)}
      _ -> {:error, :not_found}
    end
  end

  defp load_descendant_documents(rows) do
    document_ids = Enum.map(rows, fn [document_id] -> Ecto.UUID.load!(document_id) end)

    from(d in Document, where: d.id in ^document_ids)
    |> Repo.all()
    |> Map.new(&{&1.id, &1})
  end

  defp validate_exclusion_targets(document_ids, descendant_documents) do
    document_ids
    |> Enum.reduce_while({:ok, MapSet.new()}, fn document_id, {:ok, seen} ->
      cond do
        is_nil(descendant_documents[document_id]) ->
          {:halt, {:error, {:invalid_value, :exclusions}}}

        MapSet.member?(seen, document_id) ->
          {:halt, {:error, {:invalid_value, :exclusions}}}

        true ->
          {:cont, {:ok, MapSet.put(seen, document_id)}}
      end
    end)
    |> case do
      {:ok, _seen} -> :ok
      error -> error
    end
  end

  defp expand_excluded_document_ids(document_ids, descendant_documents) do
    excluded_ids = MapSet.new(document_ids)

    Enum.reduce(descendant_documents, MapSet.new(), fn {document_id, document}, acc ->
      if document_or_ancestor_excluded?(document, descendant_documents, excluded_ids) do
        MapSet.put(acc, document_id)
      else
        acc
      end
    end)
  end

  defp document_or_ancestor_excluded?(
         %Document{id: document_id, parent_id: parent_id},
         descendant_documents,
         excluded_ids
       ) do
    if MapSet.member?(excluded_ids, document_id) do
      true
    else
      case parent_id && descendant_documents[parent_id] do
        %Document{} = parent ->
          document_or_ancestor_excluded?(parent, descendant_documents, excluded_ids)

        _ ->
          false
      end
    end
  end

  defp validate_root_folder_share(%Share{scope: "folder", parent_share_id: nil}), do: :ok
  defp validate_root_folder_share(%Share{}), do: {:error, {:invalid_value, :scope}}

  defp insert_share_exclusions!(_share_id, []), do: :ok

  defp insert_share_exclusions!(share_id, document_ids) do
    now = DateTime.utc_now()

    entries =
      Enum.map(document_ids, fn document_id ->
        %{share_id: share_id, document_id: document_id, created_at: now}
      end)

    Repo.insert_all(ShareExclusion, entries,
      on_conflict: :nothing,
      conflict_target: [:share_id, :document_id]
    )

    :ok
  end

  defp delete_share_exclusions!(_share_id, []), do: :ok

  defp delete_share_exclusions!(share_id, document_ids) do
    from(e in ShareExclusion,
      where: e.share_id == ^share_id and e.document_id in ^document_ids
    )
    |> Repo.delete_all()

    :ok
  end

  defp delete_folder_child_shares!(share_id, excluded_ids) do
    if MapSet.size(excluded_ids) > 0 do
      document_ids = MapSet.to_list(excluded_ids)

      {count, nil} =
        from(s in Share,
          where: s.parent_share_id == ^share_id and s.document_id in ^document_ids
        )
        |> Repo.delete_all()

      count
    else
      0
    end
  end

  defp list_share_exclusion_ids(share_id) do
    from(e in ShareExclusion,
      where: e.share_id == ^share_id,
      order_by: [asc: e.document_id],
      select: e.document_id
    )
    |> Repo.all()
  end

  defp parse_share_update_attrs(attrs) do
    expires_event_sequence_present? =
      Map.has_key?(attrs, :expires_event_sequence) or
        Map.has_key?(attrs, "expires_event_sequence")

    max_views_present? =
      Map.has_key?(attrs, :max_views) or Map.has_key?(attrs, "max_views")

    with {:ok, expires_event_sequence} <-
           parse_share_update_integer(attrs, :expires_event_sequence),
         {:ok, max_views} <- parse_share_update_integer(attrs, :max_views) do
      update_attrs =
        %{}
        |> maybe_put_update_attr(
          :expires_event_sequence,
          expires_event_sequence_present?,
          expires_event_sequence
        )
        |> maybe_put_update_attr(:max_views, max_views_present?, max_views)

      if map_size(update_attrs) == 0 do
        {:error, :missing_update_fields}
      else
        {:ok, update_attrs}
      end
    end
  end

  defp parse_share_exclusion_update_attrs(attrs) do
    add_present? = Map.has_key?(attrs, :add) or Map.has_key?(attrs, "add")
    remove_present? = Map.has_key?(attrs, :remove) or Map.has_key?(attrs, "remove")

    with {:ok, add} <- parse_share_exclusion_id_list(attrs, :add),
         {:ok, remove} <- parse_share_exclusion_id_list(attrs, :remove),
         :ok <- validate_disjoint_exclusion_updates(add, remove) do
      if not add_present? and not remove_present? do
        {:error, :missing_update_fields}
      else
        {:ok, %{add: add, remove: remove}}
      end
    end
  end

  defp parse_share_exclusion_id_list(attrs, key) do
    case fetch_present_attr(attrs, key) do
      {:ok, values} when is_list(values) -> parse_uuid_list(values, key)
      {:ok, _value} -> {:error, {:invalid_value, key}}
      :missing -> {:ok, []}
    end
  end

  defp parse_share_key_update_attrs(attrs) do
    add_present? = Map.has_key?(attrs, :add_keys) or Map.has_key?(attrs, "add_keys")
    replace_present? = Map.has_key?(attrs, :replace_keys) or Map.has_key?(attrs, "replace_keys")

    with {:ok, add_keys} <- parse_share_key_update_list(attrs, :add_keys),
         {:ok, replace_keys} <- parse_share_key_update_list(attrs, :replace_keys) do
      if add_present? or replace_present? do
        {:ok, %{add_keys: add_keys, replace_keys: replace_keys}}
      else
        {:error, :missing_update_fields}
      end
    end
  end

  defp parse_share_key_update_list(attrs, key) do
    case fetch_present_attr(attrs, key) do
      {:ok, values} when is_list(values) -> parse_folder_share_key_update_entries(values, key)
      {:ok, _value} -> {:error, {:invalid_value, key}}
      :missing -> {:ok, []}
    end
  end

  defp parse_folder_share_key_update_entries(share_keys, field) do
    share_keys
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case parse_folder_share_key_update_entry(entry) do
        {:ok, parsed} ->
          {:cont, {:ok, [parsed | acc]}}

        {:error, reason} ->
          {:halt, normalize_share_key_update_parse_error(reason, field)}
      end
    end)
    |> reverse_parsed_list()
  end

  defp parse_folder_share_key_update_entry(entry) when is_map(entry) do
    with {:ok, share_id} <- fetch_uuid(entry, :share_id),
         {:ok, document_id} <- fetch_uuid(entry, :document_id),
         {:ok, encrypted_dek} <- fetch_binary(entry, :encrypted_dek),
         {:ok, nonce} <- fetch_binary(entry, :nonce),
         :ok <- validate_share_key_nonce(nonce) do
      {:ok,
       %{
         share_id: share_id,
         document_id: document_id,
         encrypted_dek: encrypted_dek,
         nonce: nonce
       }}
    end
  end

  defp parse_folder_share_key_update_entry(_entry), do: {:error, {:invalid_value, :share_keys}}

  defp normalize_share_key_update_parse_error({:invalid_value, :share_keys}, field),
    do: {:error, {:invalid_value, field}}

  defp normalize_share_key_update_parse_error({:missing_field, _key}, field),
    do: {:error, {:invalid_value, field}}

  defp normalize_share_key_update_parse_error(reason, _field), do: {:error, reason}

  defp validate_disjoint_exclusion_updates(add, remove) do
    add_set = MapSet.new(add)
    remove_set = MapSet.new(remove)

    cond do
      MapSet.size(add_set) != length(add) ->
        {:error, {:invalid_value, :add}}

      MapSet.size(remove_set) != length(remove) ->
        {:error, {:invalid_value, :remove}}

      not MapSet.disjoint?(add_set, remove_set) ->
        {:error, {:invalid_value, :exclusions}}

      true ->
        :ok
    end
  end

  defp parse_uuid_list(values, field) do
    values
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
      case Ecto.UUID.cast(value) do
        {:ok, uuid} -> {:cont, {:ok, [uuid | acc]}}
        :error -> {:halt, {:error, {:invalid_uuid, field}}}
      end
    end)
    |> reverse_parsed_list()
  end

  defp reverse_parsed_list({:ok, parsed}), do: {:ok, Enum.reverse(parsed)}
  defp reverse_parsed_list(error), do: error

  defp fetch_uuid(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) ->
        parse_uuid_value(value, key)

      _ ->
        {:error, {:missing_field, key}}
    end
  end

  defp parse_uuid_value(value, key) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_uuid, key}}
    end
  end

  defp fetch_binary(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  defp validate_share_key_nonce(nonce) when byte_size(nonce) == 24, do: :ok
  defp validate_share_key_nonce(_nonce), do: {:error, :invalid_nonce}

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  defp parse_share_update_integer(attrs, key) do
    case fetch_present_attr(attrs, key) do
      {:ok, nil} -> {:ok, nil}
      {:ok, value} when is_integer(value) -> parse_positive_integer(value, key)
      {:ok, _value} -> {:error, {:invalid_integer, key}}
      :missing -> {:ok, nil}
    end
  end

  defp fetch_present_attr(attrs, key) do
    cond do
      Map.has_key?(attrs, key) -> {:ok, Map.get(attrs, key)}
      Map.has_key?(attrs, to_string(key)) -> {:ok, Map.get(attrs, to_string(key))}
      true -> :missing
    end
  end

  defp parse_positive_integer(value, _key) when value > 0, do: {:ok, value}
  defp parse_positive_integer(_value, key), do: {:error, {:invalid_value, key}}

  defp maybe_put_update_attr(attrs, _key, false, _value), do: attrs
  defp maybe_put_update_attr(attrs, key, true, value), do: Map.put(attrs, key, value)

  defp fetch_manageable_share!(document_id, share_id) do
    from(s in Share,
      join: sk in ShareKey,
      on: sk.share_id == s.id,
      where: s.id == ^share_id and s.document_id == ^document_id,
      lock: "FOR UPDATE",
      select: {s, sk}
    )
    |> Repo.one()
    |> case do
      {_, _} = result -> result
      nil -> Repo.rollback(:not_found)
    end
  end

  defp update_share_keys_tx(document_id, share_id, update_attrs, key_directory) do
    {share, _share_key} = fetch_manageable_share!(document_id, share_id)
    maybe_append_share_scope_key_directory!(share, key_directory, update_attrs)

    case Shares.apply_folder_share_key_update(share, update_attrs) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp maybe_append_share_scope_key_directory!(_share, :skip_key_directory, _update_attrs),
    do: :ok

  defp maybe_append_share_scope_key_directory!(share, key_directory, update_attrs) do
    :ok = KeyDirectory.append_scope!(share, key_directory, update_attrs)

    latest_event_type =
      if update_attrs.replace_keys == [],
        do: "share_key_scope_added",
        else: "share_key_scope_replaced"

    update_latest_bootstrap_event_hash!(
      share,
      KeyDirectory.latest_event_hash!(key_directory, latest_event_type)
    )
  end

  defp update_latest_bootstrap_event_hash!(share, latest_event_hash) do
    share
    |> Share.update_settings_changeset(%{latest_bootstrap_event_hash: latest_event_hash})
    |> Repo.update()
    |> case do
      {:ok, _share} -> :ok
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp share_invalid_after_settings_update?(share) do
    Access.expired?(share)
  end

  defp fetch_share_for_document!(document_id, share_id) do
    from(s in Share,
      where: s.id == ^share_id and s.document_id == ^document_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
    |> case do
      %Share{} = share -> share
      nil -> Repo.rollback(:not_found)
    end
  end

  defp revoke_share_participant_sessions(share_id) do
    targets = share_revocation_targets(share_id)

    from(s in ShareParticipantSession, where: s.share_id == ^share_id)
    |> Repo.delete_all()

    targets
  end

  defp share_revocation_targets(share_id) do
    from(s in ShareParticipantSession,
      where: s.share_id == ^share_id,
      select: %{
        principal_id: s.principal_id,
        device_id: s.device_id
      }
    )
    |> Repo.all()
  end

  defp broadcast_share_revocations(_share_id, []), do: :ok

  defp broadcast_share_revocations(share_id, targets) do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "share:#{share_id}:revoked",
      {:share_revoked, share_id}
    )

    principal_ids =
      targets
      |> Enum.map(& &1.principal_id)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    device_ids =
      targets
      |> Enum.map(& &1.device_id)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    Enum.each(principal_ids, fn principal_id ->
      Phoenix.PubSub.broadcast(
        RefMD.PubSub,
        "share_socket:#{principal_id}",
        %Phoenix.Socket.Broadcast{
          topic: "share_socket:#{principal_id}",
          event: "disconnect",
          payload: %{}
        }
      )
    end)

    Enum.each(device_ids, fn device_id ->
      Phoenix.PubSub.broadcast(
        RefMD.PubSub,
        "share_device_revocation:#{device_id}",
        {:device_revoked, device_id}
      )
    end)
  end

  defp broadcast_share_document_revocations(_share_id, []), do: :ok

  defp broadcast_share_document_revocations(share_id, document_ids) do
    document_ids
    |> Enum.uniq()
    |> Enum.each(fn document_id ->
      Phoenix.PubSub.broadcast(
        RefMD.PubSub,
        "share_document_revocation:#{share_id}:#{document_id}",
        {:share_document_revoked, share_id, document_id}
      )
    end)
  end

  defp normalize_share_settings_result({:ok, %{share: share, revoked_targets: revoked_targets}}) do
    broadcast_share_revocations(share.id, revoked_targets)

    {:ok,
     %{
       id: share.id,
       expires_event_sequence: share.expires_event_sequence,
       max_views: share.max_views,
       view_count: share.view_count
     }}
  end

  defp normalize_share_settings_result({:error, reason}), do: {:error, reason}

  defp normalize_key_update_result({:ok, result}), do: {:ok, result}
  defp normalize_key_update_result({:error, reason}), do: {:error, reason}

  defp normalize_exclusion_update_result(
         {:ok,
          %{
            share_id: share_id,
            exclusions: exclusions,
            revoked_document_ids: revoked_document_ids
          }}
       ) do
    broadcast_share_document_revocations(share_id, revoked_document_ids)
    {:ok, %{share_id: share_id, exclusions: exclusions}}
  end

  defp normalize_exclusion_update_result({:error, reason}), do: {:error, reason}

  defp normalize_delete_result({:ok, %{share_id: share_id, revoked_targets: revoked_targets}}) do
    broadcast_share_revocations(share_id, revoked_targets)
    :ok
  end

  defp normalize_delete_result({:error, reason}), do: {:error, reason}
end
