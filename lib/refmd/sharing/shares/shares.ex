defmodule RefMD.Sharing.Shares do
  @moduledoc """
  Share provisioning and key rotation.
  """

  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Sharing.Shares.LinkSecretBackupWraps

  alias RefMD.Sharing.{
    Access,
    Input,
    KeyDirectory,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareExclusion,
    ShareKey
  }

  def get_share_permission_version(share_id) do
    case Repo.get(Share, share_id) do
      %{permission_version: version} when is_integer(version) and version > 0 -> version
      _ -> 1
    end
  end

  def share_workspace_id!(share_id) when is_binary(share_id) do
    from(s in Share,
      join: d in Document,
      on: d.id == s.document_id,
      where: s.id == ^share_id,
      select: d.workspace_id
    )
    |> Repo.one()
    |> case do
      workspace_id when is_binary(workspace_id) -> workspace_id
      _ -> raise ArgumentError, "share_workspace_not_found"
    end
  end

  def create_share(%Document{} = document, user_id, attrs) do
    with {:ok, share_id} <- Input.fetch_uuid(attrs, :id),
         {:ok, share_slug, share_slug_bytes} <- Input.fetch_url_token(attrs, :share_slug),
         {:ok, permission} <- Input.fetch_enum(attrs, :permission, ~w(view edit)),
         {:ok, scope} <- Input.fetch_enum(attrs, :scope, ~w(document folder)),
         :ok <- Input.validate_active_share_root(document),
         :ok <- Input.validate_share_scope(document, scope),
         {:ok, password_protected} <- Input.fetch_boolean(attrs, :password_protected),
         {:ok, token_prefix} <- Input.fetch_token_prefix(attrs, share_slug),
         {:ok, encrypted_dek} <- Input.fetch_binary(attrs, :encrypted_dek),
         {:ok, nonce} <- Input.fetch_optional_binary(attrs, :nonce),
         {:ok, authorization_public_key_material} <-
           Input.fetch_authorization_public_key_material(attrs),
         {:ok, share_capability_secret_commitment} <-
           Input.fetch_required_base64url_hash(attrs, :share_capability_secret_commitment),
         {:ok, password_capability_secret_commitment} <-
           Input.fetch_password_capability_secret_commitment(attrs, password_protected),
         :ok <-
           Input.validate_authorization_public_key_material(
             authorization_public_key_material,
             Blake3.hash_base64url(share_slug_bytes)
           ),
         :ok <- Input.validate_encrypted_dek(encrypted_dek, password_protected),
         :ok <- Input.validate_share_key_nonce(nonce, password_protected),
         {:ok, salt} <- Input.fetch_optional_binary(attrs, :salt),
         {:ok, kdf_params} <- Input.fetch_optional_map(attrs, :kdf_params),
         {:ok, client_pin_bootstrap_hash} <-
           Input.fetch_required_base64url_hash(
             attrs,
             :authenticated_workspace_pin_bootstrap_hash
           ),
         {:ok, pin_bootstrap} <-
           Input.fetch_required_map(attrs, :authenticated_workspace_pin_bootstrap),
         :ok <-
           Input.validate_password_share_fields(
             password_protected,
             salt,
             kdf_params
           ),
         {:ok, auth_key} <- Input.fetch_password_auth_key(attrs, password_protected),
         {:ok, auth_key_wrap} <- wrap_password_auth_key(auth_key, share_id),
         {:ok, expires_event_sequence} <-
           Input.fetch_required_positive_integer(attrs, :expires_event_sequence),
         {:ok, max_views} <- Input.fetch_required_positive_integer(attrs, :max_views),
         {:ok, share_keys} <-
           Input.fetch_folder_share_keys(attrs, scope, password_protected),
         {:ok, exclusions} <- Input.fetch_folder_share_exclusions(attrs, scope),
         {:ok, key_directory_events, key_directory_checkpoint} <-
           KeyDirectory.fetch_append(attrs),
         {:ok, created_event_ref} <-
           KeyDirectory.share_created_event_ref(key_directory_events),
         :ok <-
           KeyDirectory.validate_workspace_pin_bootstrap_hash(
             document.workspace_id,
             pin_bootstrap,
             client_pin_bootstrap_hash,
             created_event_ref.sequence
           ),
         {:ok, capability_context_hash} <-
           KeyDirectory.share_created_capability_context_hash(key_directory_events),
         {:ok, share_link_secret_backup_wraps} <-
           fetch_share_link_secret_backup_wraps(attrs) do
      create_share_attrs = %{
        share_id: share_id,
        share_slug: share_slug,
        share_slug_bytes: share_slug_bytes,
        token_hash: Blake3.hash_base64url(share_slug_bytes),
        token_prefix: token_prefix,
        authorization_public_key_material: authorization_public_key_material,
        share_capability_secret_commitment: share_capability_secret_commitment,
        password_capability_secret_commitment: password_capability_secret_commitment,
        capability_context_hash: capability_context_hash,
        created_event_hash: created_event_ref.hash,
        created_event_sequence: created_event_ref.sequence,
        latest_bootstrap_event_hash: created_event_ref.hash,
        permission: permission,
        scope: scope,
        password_protected: password_protected,
        encrypted_dek: encrypted_dek,
        nonce: nonce,
        salt: salt,
        kdf_params: kdf_params,
        encrypted_auth_key: auth_key_wrap && auth_key_wrap.ciphertext,
        auth_key_nonce: auth_key_wrap && auth_key_wrap.nonce,
        auth_key_server_key_id: auth_key_wrap && auth_key_wrap.key_id,
        authenticated_workspace_pin_bootstrap_hash: client_pin_bootstrap_hash,
        authenticated_workspace_pin_bootstrap_checkpoint: pin_bootstrap,
        max_views: max_views,
        expires_event_sequence: expires_event_sequence,
        share_keys: share_keys,
        exclusions: exclusions,
        key_directory_events: key_directory_events,
        key_directory_checkpoint: key_directory_checkpoint,
        created_by: user_id,
        actor_device_id: dual_key_get(attrs, :actor_device_id),
        share_link_secret_backup_wraps: share_link_secret_backup_wraps
      }

      case scope do
        "document" -> create_share_tx(document, user_id, create_share_attrs)
        "folder" -> create_folder_share_tx(document, user_id, create_share_attrs)
      end
    end
  end

  def apply_folder_share_key_update(share, %{add_keys: add_keys, replace_keys: replace_keys}) do
    with :ok <- validate_root_folder_share(share),
         {:ok, descendant_documents} <- list_folder_descendant_documents(share.document_id),
         {:ok, valid_add_keys} <-
           validate_folder_share_key_add_entries(
             share,
             add_keys,
             descendant_documents
           ),
         {:ok, valid_replace_keys} <-
           validate_folder_share_key_replace_entries(share, replace_keys, descendant_documents),
         :ok <- validate_disjoint_share_key_updates(valid_add_keys, valid_replace_keys),
         :ok <- insert_added_folder_child_shares(share, valid_add_keys, descendant_documents),
         :ok <- replace_folder_child_share_keys(valid_replace_keys) do
      {:ok,
       %{
         share_id: share.id,
         added: Enum.map(valid_add_keys, & &1.document_id),
         replaced: Enum.map(valid_replace_keys, & &1.document_id)
       }}
    end
  end

  defp create_share_tx(document, user_id, attrs) do
    Repo.transaction(fn ->
      insert_share_records(document, user_id, attrs)
    end)
    |> normalize_transaction_result()
  end

  defp insert_share_records(document, user_id, attrs) do
    with :ok <- append_share_key_directory!(document, attrs),
         {:ok, share} <- insert_share(document, user_id, attrs),
         :ok <- LinkSecretBackupWraps.insert!(share, document, attrs),
         {:ok, _share_key} <- insert_share_key(share, document, attrs),
         {:ok, _token} <- insert_root_document_token(share.id, document.id) do
      %{
        share: share,
        share_slug: attrs.share_slug,
        created_event_sequence: attrs.created_event_sequence
      }
    else
      {:error, %Ecto.Changeset{} = changeset} -> Repo.rollback(changeset)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp create_folder_share_tx(folder, user_id, attrs) do
    Repo.transaction(fn ->
      with :ok <- append_share_key_directory!(folder, attrs),
           {:ok, root_share} <- insert_share(folder, user_id, attrs),
           :ok <- LinkSecretBackupWraps.insert!(root_share, folder, attrs),
           {:ok, _share_key} <- insert_share_key(root_share, folder, attrs),
           {:ok, _token} <- insert_root_folder_token(root_share.id, folder.id),
           :ok <- insert_folder_child_shares(root_share, folder, user_id, attrs),
           :ok <- insert_share_exclusions(root_share.id, attrs.exclusions) do
        %{
          share: root_share,
          share_slug: attrs.share_slug,
          created_event_sequence: attrs.created_event_sequence
        }
      else
        {:error, %Ecto.Changeset{} = changeset} -> Repo.rollback(changeset)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  end

  defp insert_share(document, user_id, attrs) do
    %Share{}
    |> Share.changeset(%{
      id: attrs.share_id,
      document_id: document.id,
      parent_share_id: Map.get(attrs, :parent_share_id),
      scope: attrs.scope,
      token_hash: attrs.token_hash,
      token_prefix: attrs.token_prefix,
      authorization_public_key_material: attrs.authorization_public_key_material,
      share_capability_secret_commitment: attrs.share_capability_secret_commitment,
      password_capability_secret_commitment: attrs.password_capability_secret_commitment,
      capability_context_hash: attrs.capability_context_hash,
      created_event_hash: attrs.created_event_hash,
      latest_bootstrap_event_hash:
        Map.get(attrs, :latest_bootstrap_event_hash, attrs.created_event_hash),
      authenticated_workspace_pin_bootstrap_hash:
        attrs.authenticated_workspace_pin_bootstrap_hash,
      authenticated_workspace_pin_bootstrap_checkpoint:
        attrs.authenticated_workspace_pin_bootstrap_checkpoint,
      permission: attrs.permission,
      password_protected: attrs.password_protected,
      max_views: attrs.max_views,
      view_count: 0,
      created_by: user_id,
      expires_event_sequence: attrs.expires_event_sequence
    })
    |> Repo.insert()
  end

  defp append_share_key_directory!(document, attrs) do
    KeyDirectory.append!(document, attrs)
  end

  defp fetch_share_link_secret_backup_wraps(attrs) do
    wraps = dual_key_get(attrs, :share_link_secret_backup_wraps)

    if is_list(wraps) and wraps != [],
      do: {:ok, wraps},
      else: {:error, :missing_share_link_secret_backup_wraps}
  end

  defp insert_share_key(share, document, attrs) do
    %ShareKey{}
    |> ShareKey.changeset(%{
      share_id: share.id,
      document_id: document.id,
      encrypted_dek: attrs.encrypted_dek,
      nonce: attrs.nonce,
      salt: attrs.salt,
      kdf_params: attrs.kdf_params,
      encrypted_auth_key: Map.get(attrs, :encrypted_auth_key),
      auth_key_nonce: Map.get(attrs, :auth_key_nonce),
      auth_key_server_key_id: Map.get(attrs, :auth_key_server_key_id)
    })
    |> Repo.insert()
  end

  defp wrap_password_auth_key(nil, _share_id), do: {:ok, nil}

  defp wrap_password_auth_key(auth_key, share_id),
    do: Encryption.encrypt_share_auth_key(auth_key, share_id)

  defp insert_root_document_token(share_id, document_id) do
    %SharedDocumentToken{}
    |> SharedDocumentToken.changeset(%{
      share_id: share_id,
      document_id: document_id,
      token: generate_opaque_shared_token()
    })
    |> Repo.insert()
  end

  defp insert_root_folder_token(share_id, document_id) do
    %SharedFolderToken{created_at: DateTime.utc_now()}
    |> SharedFolderToken.changeset(%{
      share_id: share_id,
      document_id: document_id,
      token: generate_opaque_shared_token()
    })
    |> Repo.insert()
  end

  defp insert_share_exclusions(_share_id, []), do: :ok

  defp insert_share_exclusions(share_id, document_ids) do
    Enum.reduce_while(document_ids, :ok, fn document_id, :ok ->
      case %ShareExclusion{}
           |> ShareExclusion.changeset(%{share_id: share_id, document_id: document_id})
           |> Repo.insert(on_conflict: :nothing, conflict_target: [:share_id, :document_id]) do
        {:ok, _exclusion} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp insert_folder_child_shares(root_share, folder, user_id, attrs) do
    with {:ok, descendant_documents} <- list_folder_descendant_documents(folder.id),
         {:ok, share_keys_by_document_id} <-
           validate_folder_share_key_entries(
             attrs.share_keys,
             descendant_documents,
             attrs.exclusions
           ) do
      insert_folder_child_share_entries(
        share_keys_by_document_id,
        descendant_documents,
        root_share,
        user_id,
        attrs
      )
    end
  end

  defp insert_folder_child_share_entries(
         share_keys_by_document_id,
         descendant_documents,
         root_share,
         user_id,
         attrs
       ) do
    Enum.reduce_while(share_keys_by_document_id, :ok, fn {_document_id, entry}, :ok ->
      document = descendant_documents[entry.document_id]

      case insert_folder_child_share(root_share, document, user_id, attrs, entry) do
        {:ok, _child_share} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp insert_added_folder_child_shares(root_share, share_keys, descendant_documents) do
    attrs = %{
      permission: root_share.permission,
      password_protected: root_share.password_protected,
      share_capability_secret_commitment: root_share.share_capability_secret_commitment,
      password_capability_secret_commitment: root_share.password_capability_secret_commitment,
      capability_context_hash: root_share.capability_context_hash,
      created_event_hash: root_share.created_event_hash,
      latest_bootstrap_event_hash: root_share.latest_bootstrap_event_hash,
      authenticated_workspace_pin_bootstrap_hash:
        root_share.authenticated_workspace_pin_bootstrap_hash,
      authenticated_workspace_pin_bootstrap_checkpoint:
        root_share.authenticated_workspace_pin_bootstrap_checkpoint,
      max_views: root_share.max_views,
      expires_event_sequence: root_share.expires_event_sequence
    }

    Enum.reduce_while(share_keys, :ok, fn entry, :ok ->
      document = descendant_documents[entry.document_id]

      case insert_folder_child_share(root_share, document, root_share.created_by, attrs, entry) do
        {:ok, _child_share} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp replace_folder_child_share_keys(share_keys) do
    Enum.reduce_while(share_keys, :ok, fn entry, :ok ->
      case replace_folder_child_share_key(entry) do
        {:ok, _share_key} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp replace_folder_child_share_key(%{child_share: child_share} = entry) do
    case Repo.get(ShareKey, child_share.id) do
      %ShareKey{} = share_key ->
        share_key
        |> ShareKey.changeset(%{
          encrypted_dek: entry.encrypted_dek,
          nonce: entry.nonce
        })
        |> Repo.update()

      nil ->
        {:error, {:invalid_value, :replace_keys}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp insert_folder_child_share(root_share, document, user_id, attrs, share_key_attrs) do
    child_share_attrs =
      attrs
      |> Map.put(:share_id, share_key_attrs.share_id)
      |> build_internal_share_attrs(document, root_share.id)
      |> Map.merge(%{
        encrypted_dek: share_key_attrs.encrypted_dek,
        nonce: share_key_attrs.nonce,
        password_protected: false,
        salt: nil,
        kdf_params: nil,
        scope: document_share_scope(document)
      })

    with {:ok, child_share} <- insert_share(document, user_id, child_share_attrs),
         {:ok, _share_key} <- insert_share_key(child_share, document, child_share_attrs),
         {:ok, _token} <- insert_child_share_token(child_share, document) do
      {:ok, child_share}
    end
  end

  defp document_share_scope(%Document{doc_type: "folder"}), do: "folder"
  defp document_share_scope(%Document{}), do: "document"

  defp insert_child_share_token(%Share{} = share, %Document{doc_type: "folder"} = document) do
    insert_root_folder_token(share.id, document.id)
  end

  defp insert_child_share_token(%Share{} = share, %Document{} = document) do
    insert_root_document_token(share.id, document.id)
  end

  defp build_internal_share_attrs(attrs, document, parent_share_id) do
    {child_share_slug, child_share_slug_bytes} = generate_url_token()

    %{
      share_id: attrs.share_id,
      share_slug: child_share_slug,
      share_slug_bytes: child_share_slug_bytes,
      token_hash: Blake3.hash_base64url(child_share_slug_bytes),
      token_prefix: String.slice(child_share_slug, 0, 4),
      authorization_public_key_material: nil,
      share_capability_secret_commitment: attrs.share_capability_secret_commitment,
      password_capability_secret_commitment: attrs.password_capability_secret_commitment,
      capability_context_hash: attrs.capability_context_hash,
      created_event_hash: attrs.created_event_hash,
      latest_bootstrap_event_hash:
        Map.get(attrs, :latest_bootstrap_event_hash, attrs.created_event_hash),
      authenticated_workspace_pin_bootstrap_hash:
        attrs.authenticated_workspace_pin_bootstrap_hash,
      authenticated_workspace_pin_bootstrap_checkpoint:
        attrs.authenticated_workspace_pin_bootstrap_checkpoint,
      permission: attrs.permission,
      password_protected: attrs.password_protected,
      max_views: attrs.max_views,
      expires_event_sequence: attrs.expires_event_sequence,
      document_id: document.id,
      parent_share_id: parent_share_id
    }
  end

  defp generate_url_token(bytes \\ 16) do
    raw = :crypto.strong_rand_bytes(bytes)
    {Base.url_encode64(raw, padding: false), raw}
  end

  defp generate_opaque_shared_token do
    {token, _bytes} = generate_url_token()
    token
  end

  defp get_folder_child_share(root_share_id, share_id, document_id) do
    from(s in Share,
      join: d in Document,
      on: d.id == s.document_id,
      join: sk in ShareKey,
      on: sk.share_id == s.id,
      left_join: dt in SharedDocumentToken,
      on: dt.share_id == s.id and dt.document_id == s.document_id,
      left_join: ft in SharedFolderToken,
      on: ft.share_id == s.id and ft.document_id == s.document_id,
      where: s.id == ^share_id,
      where: s.parent_share_id == ^root_share_id,
      where: s.document_id == ^document_id,
      where: s.scope == d.doc_type,
      where:
        fragment(
          "(? = 'folder' AND ? IS NOT NULL) OR (? = 'document' AND ? IS NOT NULL)",
          d.doc_type,
          ft.share_id,
          d.doc_type,
          dt.share_id
        )
    )
    |> Repo.one()
  end

  defp share_id_exists?(share_id) do
    from(s in Share, where: s.id == ^share_id)
    |> Repo.exists?()
  end

  defp folder_child_share_exists?(root_share_id, document_id) do
    from(s in Share,
      join: d in Document,
      on: d.id == s.document_id,
      where:
        s.parent_share_id == ^root_share_id and s.document_id == ^document_id and
          s.scope == d.doc_type
    )
    |> Repo.exists?()
  end

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

  defp validate_folder_share_key_entries(share_keys, descendant_documents, exclusions) do
    with :ok <- validate_exclusion_targets(exclusions, descendant_documents) do
      expanded_exclusion_ids = expand_excluded_document_ids(exclusions, descendant_documents)

      reduce_folder_share_keys(share_keys, descendant_documents, expanded_exclusion_ids)
      |> validate_all_folder_share_keys_present(descendant_documents, expanded_exclusion_ids)
    end
  end

  defp validate_folder_share_key_add_entries(
         root_share,
         share_keys,
         descendant_documents
       ) do
    expanded_exclusion_ids =
      root_share.id
      |> list_share_exclusion_ids()
      |> expand_excluded_document_ids(descendant_documents)

    share_keys
    |> Enum.reduce_while({:ok, [], MapSet.new(), MapSet.new()}, fn share_key,
                                                                   {:ok, acc, document_ids,
                                                                    share_ids} ->
      case validate_folder_share_key_add_entry(
             share_key,
             root_share,
             descendant_documents,
             expanded_exclusion_ids,
             document_ids,
             share_ids
           ) do
        :ok ->
          {:cont,
           {:ok, [share_key | acc], MapSet.put(document_ids, share_key.document_id),
            MapSet.put(share_ids, share_key.share_id)}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> validate_added_folder_share_key_paths(
      root_share.id,
      root_share.document_id,
      descendant_documents
    )
  end

  defp validate_added_folder_share_key_paths(
         {:ok, valid_keys, document_ids, _share_ids},
         root_share_id,
         root_folder_id,
         descendant_documents
       ) do
    valid_keys = Enum.reverse(valid_keys)

    valid_keys
    |> Enum.reduce_while(:ok, fn share_key, :ok ->
      document = descendant_documents[share_key.document_id]

      case validate_added_folder_share_key_path(
             document,
             root_share_id,
             root_folder_id,
             document_ids,
             descendant_documents
           ) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      :ok -> {:ok, valid_keys}
      error -> error
    end
  end

  defp validate_added_folder_share_key_paths(
         error,
         _root_share_id,
         _root_folder_id,
         _descendant_documents
       ),
       do: error

  defp validate_added_folder_share_key_path(
         %Document{parent_id: parent_id},
         _root_share_id,
         root_folder_id,
         _added_document_ids,
         _descendant_documents
       )
       when parent_id == root_folder_id,
       do: :ok

  defp validate_added_folder_share_key_path(
         %Document{parent_id: parent_id},
         root_share_id,
         root_folder_id,
         added_document_ids,
         descendant_documents
       ) do
    with %Document{} = parent <- descendant_documents[parent_id],
         true <-
           folder_share_key_path_segment_present?(root_share_id, parent_id, added_document_ids) do
      validate_added_folder_share_key_path(
        parent,
        root_share_id,
        root_folder_id,
        added_document_ids,
        descendant_documents
      )
    else
      _ -> {:error, {:invalid_value, :add_keys}}
    end
  end

  defp folder_share_key_path_segment_present?(root_share_id, document_id, added_document_ids) do
    MapSet.member?(added_document_ids, document_id) or
      Access.folder_child_share_ready?(root_share_id, document_id)
  end

  defp validate_folder_share_key_replace_entries(root_share, share_keys, descendant_documents) do
    expanded_exclusion_ids =
      root_share.id
      |> list_share_exclusion_ids()
      |> expand_excluded_document_ids(descendant_documents)

    share_keys
    |> Enum.reduce_while({:ok, [], MapSet.new(), MapSet.new()}, fn share_key,
                                                                   {:ok, acc, document_ids,
                                                                    share_ids} ->
      case validate_folder_share_key_replace_entry(
             share_key,
             root_share,
             root_share.document_id,
             descendant_documents,
             expanded_exclusion_ids,
             document_ids,
             share_ids
           ) do
        {:ok, child_share} ->
          {:cont,
           {:ok, [Map.put(share_key, :child_share, child_share) | acc],
            MapSet.put(document_ids, share_key.document_id),
            MapSet.put(share_ids, share_key.share_id)}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, valid_keys, _document_ids, _share_ids} -> {:ok, Enum.reverse(valid_keys)}
      error -> error
    end
  end

  defp validate_disjoint_share_key_updates(add_keys, replace_keys) do
    add_document_ids = add_keys |> Enum.map(& &1.document_id) |> MapSet.new()
    replace_document_ids = replace_keys |> Enum.map(& &1.document_id) |> MapSet.new()
    add_share_ids = add_keys |> Enum.map(& &1.share_id) |> MapSet.new()
    replace_share_ids = replace_keys |> Enum.map(& &1.share_id) |> MapSet.new()

    cond do
      not MapSet.disjoint?(add_document_ids, replace_document_ids) ->
        {:error, {:invalid_value, :add_keys}}

      not MapSet.disjoint?(add_share_ids, replace_share_ids) ->
        {:error, {:invalid_value, :add_keys}}

      true ->
        :ok
    end
  end

  defp validate_folder_share_key_add_entry(
         share_key,
         root_share,
         descendant_documents,
         expanded_exclusion_ids,
         document_ids,
         share_ids
       ) do
    with :ok <- validate_password_protected_share_key_nonce(root_share, share_key, :add_keys) do
      cond do
        is_nil(descendant_documents[share_key.document_id]) ->
          {:error, {:invalid_value, :add_keys}}

        MapSet.member?(expanded_exclusion_ids, share_key.document_id) ->
          {:error, {:invalid_value, :add_keys}}

        duplicate_folder_share_key_entry?(share_key, document_ids, share_ids) ->
          {:error, {:invalid_value, :add_keys}}

        true ->
          validate_new_folder_child_share(root_share.id, share_key.document_id)
      end
    end
  end

  defp duplicate_folder_share_key_entry?(share_key, document_ids, share_ids) do
    MapSet.member?(document_ids, share_key.document_id) or
      MapSet.member?(share_ids, share_key.share_id) or
      share_id_exists?(share_key.share_id)
  end

  defp validate_new_folder_child_share(root_share_id, document_id) do
    case folder_child_share_exists?(root_share_id, document_id) do
      true -> {:error, {:invalid_value, :add_keys}}
      false -> :ok
    end
  end

  defp validate_folder_share_key_replace_entry(
         share_key,
         root_share,
         root_folder_id,
         descendant_documents,
         expanded_exclusion_ids,
         document_ids,
         share_ids
       ) do
    cond do
      is_nil(descendant_documents[share_key.document_id]) ->
        {:error, {:invalid_value, :replace_keys}}

      MapSet.member?(expanded_exclusion_ids, share_key.document_id) ->
        {:error, {:invalid_value, :replace_keys}}

      MapSet.member?(document_ids, share_key.document_id) ->
        {:error, {:invalid_value, :replace_keys}}

      MapSet.member?(share_ids, share_key.share_id) ->
        {:error, {:invalid_value, :replace_keys}}

      true ->
        with :ok <-
               validate_password_protected_share_key_nonce(root_share, share_key, :replace_keys) do
          validate_existing_folder_child_share(
            root_share.id,
            root_folder_id,
            share_key,
            descendant_documents
          )
        end
    end
  end

  defp validate_password_protected_share_key_nonce(root_share, share_key, field) do
    with :ok <-
           Input.validate_encrypted_dek(
             share_key.encrypted_dek,
             root_share.password_protected
           ),
         :ok <-
           Input.validate_share_key_nonce(share_key.nonce, root_share.password_protected) do
      :ok
    else
      {:error, error} when error in [:invalid_encrypted_dek, :invalid_nonce] ->
        {:error, {:invalid_value, field}}
    end
  end

  defp validate_existing_folder_child_share(
         root_share_id,
         root_folder_id,
         share_key,
         descendant_documents
       ) do
    with %Share{} = child_share <-
           get_folder_child_share(root_share_id, share_key.share_id, share_key.document_id),
         %Document{} = document <- descendant_documents[share_key.document_id],
         :ok <-
           validate_added_folder_share_key_path(
             document,
             root_share_id,
             root_folder_id,
             MapSet.new(),
             descendant_documents
           ) do
      {:ok, child_share}
    else
      _ -> {:error, {:invalid_value, :replace_keys}}
    end
  end

  defp reduce_folder_share_keys(share_keys, descendant_documents, expanded_exclusion_ids) do
    Enum.reduce_while(share_keys, {:ok, %{}}, fn share_key, {:ok, acc} ->
      case validate_folder_share_key_entry(
             share_key,
             acc,
             descendant_documents,
             expanded_exclusion_ids
           ) do
        :ok -> {:cont, {:ok, Map.put(acc, share_key.document_id, share_key)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp validate_folder_share_key_entry(
         share_key,
         acc,
         descendant_documents,
         expanded_exclusion_ids
       ) do
    cond do
      is_nil(descendant_documents[share_key.document_id]) ->
        {:error, {:invalid_value, :share_keys}}

      MapSet.member?(expanded_exclusion_ids, share_key.document_id) ->
        {:error, {:invalid_value, :share_keys}}

      Map.has_key?(acc, share_key.document_id) ->
        {:error, {:invalid_value, :share_keys}}

      true ->
        :ok
    end
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

  defp validate_all_folder_share_keys_present(
         {:error, _reason} = error,
         _descendant_documents,
         _expanded_exclusion_ids
       ),
       do: error

  defp validate_all_folder_share_keys_present(
         {:ok, share_keys_by_document_id},
         descendant_documents,
         expanded_exclusion_ids
       ) do
    expected_ids =
      descendant_documents
      |> Map.keys()
      |> MapSet.new()
      |> MapSet.difference(expanded_exclusion_ids)

    actual_ids = MapSet.new(Map.keys(share_keys_by_document_id))

    if MapSet.equal?(expected_ids, actual_ids) do
      {:ok, share_keys_by_document_id}
    else
      {:error, {:invalid_value, :share_keys}}
    end
  end

  defp validate_root_folder_share(%Share{scope: "folder", parent_share_id: nil}), do: :ok

  defp validate_root_folder_share(%Share{}), do: {:error, {:invalid_value, :scope}}

  defp list_share_exclusion_ids(share_id) do
    from(e in ShareExclusion,
      where: e.share_id == ^share_id,
      order_by: [asc: e.document_id],
      select: e.document_id
    )
    |> Repo.all()
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end
end
