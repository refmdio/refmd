defmodule RefMD.Sharing.Shares do
  @moduledoc """
  Share provisioning and key rotation.
  """

  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.Document
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Access,
    ServerEnvelope,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareExclusion,
    ShareKey
  }

  @type create_share_result ::
          {:ok,
           %{
             share: Share.t(),
             share_slug: String.t(),
             share_manage_token: String.t()
           }}
          | {:error, term()}

  @spec create_share(Document.t(), Ecto.UUID.t(), map()) :: create_share_result()
  def create_share(%Document{} = document, user_id, attrs) do
    with {:ok, share_id} <- fetch_uuid(attrs, :id),
         {:ok, share_slug, share_slug_bytes} <- fetch_url_token(attrs, :share_slug),
         {:ok, permission} <- fetch_enum(attrs, :permission, ~w(view edit)),
         {:ok, scope} <- fetch_enum(attrs, :scope, ~w(document folder)),
         :ok <- validate_active_share_root(document),
         :ok <- validate_share_scope(document, scope),
         {:ok, password_protected} <- fetch_boolean(attrs, :password_protected),
         {:ok, token_prefix} <- fetch_token_prefix(attrs, share_slug),
         {:ok, encrypted_dek} <- fetch_binary(attrs, :encrypted_dek),
         {:ok, nonce} <- fetch_optional_binary(attrs, :nonce),
         :ok <- validate_encrypted_dek(encrypted_dek, password_protected),
         :ok <- validate_share_key_nonce(nonce, password_protected),
         {:ok, salt} <- fetch_optional_binary(attrs, :salt),
         {:ok, kdf_params} <- fetch_optional_map(attrs, :kdf_params),
         {:ok, auth_key} <- fetch_optional_binary(attrs, :auth_key),
         :ok <- validate_password_share_fields(password_protected, salt, kdf_params, auth_key),
         {:ok, expires_at} <- fetch_optional_datetime(attrs, :expires_at),
         {:ok, access_limit} <- fetch_optional_non_negative_integer(attrs, :access_limit),
         {:ok, share_keys} <- fetch_folder_share_keys(attrs, scope, password_protected),
         {:ok, exclusions} <- fetch_folder_share_exclusions(attrs, scope) do
      {manage_token, manage_token_bytes} = generate_url_token()

      create_share_attrs = %{
        share_id: share_id,
        share_slug: share_slug,
        share_slug_bytes: share_slug_bytes,
        token_hash: Blake3.hash_base64url(share_slug_bytes),
        token_prefix: token_prefix,
        permission: permission,
        scope: scope,
        password_protected: password_protected,
        encrypted_dek: encrypted_dek,
        nonce: nonce,
        salt: salt,
        kdf_params: kdf_params,
        auth_key: auth_key,
        access_limit: access_limit,
        expires_at: expires_at,
        manage_token_hash: Blake3.hash_base64url(manage_token_bytes),
        share_manage_token: manage_token,
        share_keys: share_keys,
        exclusions: exclusions
      }

      case scope do
        "document" -> create_share_tx(document, user_id, create_share_attrs)
        "folder" -> create_folder_share_tx(document, user_id, create_share_attrs)
      end
    end
  end

  @spec apply_folder_share_key_update(Share.t(), %{
          required(:add_keys) => [map()],
          required(:replace_keys) => [map()]
        }) ::
          {:ok, %{share_id: Ecto.UUID.t(), added: [Ecto.UUID.t()], replaced: [Ecto.UUID.t()]}}
          | {:error, term()}
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
    with {:ok, share} <- insert_share(document, user_id, attrs),
         {:ok, _share_key} <- insert_share_key(share, document, attrs),
         {:ok, _token} <- insert_root_document_token(share.id, document.id) do
      %{share: share, share_slug: attrs.share_slug, share_manage_token: attrs.share_manage_token}
    else
      {:error, %Ecto.Changeset{} = changeset} -> Repo.rollback(changeset)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp create_folder_share_tx(folder, user_id, attrs) do
    Repo.transaction(fn ->
      with {:ok, root_share} <- insert_share(folder, user_id, attrs),
           {:ok, _share_key} <- insert_share_key(root_share, folder, attrs),
           {:ok, _token} <- insert_root_folder_token(root_share.id, folder.id),
           :ok <- insert_folder_child_shares(root_share, folder, user_id, attrs),
           :ok <- insert_share_exclusions(root_share.id, attrs.exclusions) do
        %{
          share: root_share,
          share_slug: attrs.share_slug,
          share_manage_token: attrs.share_manage_token
        }
      else
        {:error, %Ecto.Changeset{} = changeset} -> Repo.rollback(changeset)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> normalize_transaction_result()
  end

  defp insert_share(document, user_id, attrs) do
    {:ok, wrapped_slug} =
      ServerEnvelope.encrypt_share_slug(attrs.share_slug_bytes, attrs.share_id)

    %Share{}
    |> Share.changeset(%{
      id: attrs.share_id,
      document_id: document.id,
      parent_share_id: Map.get(attrs, :parent_share_id),
      scope: attrs.scope,
      token_hash: attrs.token_hash,
      token_prefix: attrs.token_prefix,
      slug_ciphertext: wrapped_slug.ciphertext,
      slug_nonce: wrapped_slug.nonce,
      slug_key_id: wrapped_slug.key_id,
      permission: attrs.permission,
      password_protected: attrs.password_protected,
      access_limit: attrs.access_limit,
      access_count: 0,
      created_by: user_id,
      expires_at: attrs.expires_at
    })
    |> Repo.insert()
  end

  defp insert_share_key(share, document, attrs) do
    with {:ok, wrapped} <-
           ServerEnvelope.encrypt_share_dek(attrs.encrypted_dek, share.id, document.id),
         {:ok, wrapped_auth_key} <-
           maybe_wrap_share_auth_key(attrs.password_protected, attrs.auth_key, share.id) do
      %ShareKey{}
      |> ShareKey.changeset(%{
        share_id: share.id,
        document_id: document.id,
        encrypted_dek: wrapped.ciphertext,
        nonce: attrs.nonce,
        salt: attrs.salt,
        kdf_params: attrs.kdf_params,
        encrypted_auth_key: wrapped_auth_key && wrapped_auth_key.ciphertext,
        auth_key_nonce: wrapped_auth_key && wrapped_auth_key.nonce,
        dek_server_nonce: wrapped.nonce,
        server_key_id: wrapped.key_id,
        manage_token_hash: attrs.manage_token_hash
      })
      |> Repo.insert()
    end
  end

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
      access_limit: root_share.access_limit,
      expires_at: root_share.expires_at
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
    with %ShareKey{} = share_key <- Repo.get(ShareKey, child_share.id),
         {:ok, wrapped} <-
           ServerEnvelope.encrypt_share_dek(
             entry.encrypted_dek,
             child_share.id,
             entry.document_id
           ) do
      share_key
      |> ShareKey.changeset(%{
        encrypted_dek: wrapped.ciphertext,
        nonce: entry.nonce,
        dek_server_nonce: wrapped.nonce,
        server_key_id: wrapped.key_id
      })
      |> Repo.update()
    else
      nil -> {:error, {:invalid_value, :replace_keys}}
      {:error, reason} -> {:error, reason}
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
        auth_key: nil,
        manage_token_hash: random_manage_token_hash(),
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
      permission: attrs.permission,
      password_protected: attrs.password_protected,
      access_limit: attrs.access_limit,
      expires_at: attrs.expires_at,
      document_id: document.id,
      parent_share_id: parent_share_id
    }
  end

  defp maybe_wrap_share_auth_key(false, _auth_key, _share_id), do: {:ok, nil}

  defp maybe_wrap_share_auth_key(true, auth_key, share_id) when is_binary(auth_key) do
    ServerEnvelope.encrypt_share_auth_key(auth_key, share_id)
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

  defp fetch_uuid(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
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

  defp fetch_enum(attrs, key, allowed) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) ->
        if value in allowed, do: {:ok, value}, else: {:error, {:invalid_value, key}}

      nil ->
        {:error, {:missing_field, key}}

      _ ->
        {:error, {:invalid_value, key}}
    end
  end

  defp fetch_boolean(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_boolean(value) -> {:ok, value}
      nil -> {:error, {:missing_field, key}}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  defp fetch_binary(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  defp fetch_optional_binary(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      nil -> {:ok, nil}
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  defp fetch_optional_map(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      nil -> {:ok, nil}
      value when is_map(value) -> {:ok, value}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  defp fetch_optional_datetime(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case DateTime.from_iso8601(value) do
          {:ok, datetime, _} -> {:ok, datetime}
          _ -> {:error, {:invalid_datetime, key}}
        end

      _ ->
        {:error, {:invalid_datetime, key}}
    end
  end

  defp fetch_optional_non_negative_integer(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      nil -> {:ok, nil}
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _ -> {:error, {:invalid_integer, key}}
    end
  end

  defp fetch_folder_share_keys(attrs, "document", _password_protected) do
    case Map.get(attrs, :share_keys) || Map.get(attrs, "share_keys") do
      nil -> {:ok, []}
      _ -> {:error, {:invalid_value, :share_keys}}
    end
  end

  defp fetch_folder_share_keys(attrs, "folder", password_protected) do
    case Map.get(attrs, :share_keys) || Map.get(attrs, "share_keys") do
      nil ->
        {:error, {:missing_field, :share_keys}}

      [] ->
        {:ok, []}

      share_keys when is_list(share_keys) ->
        parse_folder_share_key_entries(share_keys, password_protected)

      _ ->
        {:error, {:invalid_value, :share_keys}}
    end
  end

  defp parse_folder_share_key_entries(share_keys, password_protected) do
    share_keys
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case parse_folder_share_key_entry(entry, password_protected) do
        {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_parsed_list()
  end

  defp parse_folder_share_key_entry(entry, password_protected) when is_map(entry) do
    with {:ok, share_id} <- fetch_uuid(entry, :share_id),
         {:ok, document_id} <- fetch_uuid(entry, :document_id),
         {:ok, encrypted_dek} <- fetch_binary(entry, :encrypted_dek),
         {:ok, nonce} <- fetch_optional_binary(entry, :nonce),
         :ok <- validate_encrypted_dek(encrypted_dek, password_protected),
         :ok <- validate_share_key_nonce(nonce, password_protected) do
      {:ok,
       %{
         share_id: share_id,
         document_id: document_id,
         encrypted_dek: encrypted_dek,
         nonce: nonce
       }}
    end
  end

  defp parse_folder_share_key_entry(_entry, _password_protected),
    do: {:error, {:invalid_value, :share_keys}}

  defp fetch_folder_share_exclusions(attrs, "document") do
    case Map.get(attrs, :exclusions) || Map.get(attrs, "exclusions") do
      nil -> {:ok, []}
      _ -> {:error, {:invalid_value, :exclusions}}
    end
  end

  defp fetch_folder_share_exclusions(attrs, "folder") do
    case Map.get(attrs, :exclusions) || Map.get(attrs, "exclusions") do
      nil -> {:ok, []}
      exclusions when is_list(exclusions) -> parse_uuid_list(exclusions, :exclusions)
      _ -> {:error, {:invalid_value, :exclusions}}
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

  defp validate_share_scope(%Document{doc_type: "document"}, "document"), do: :ok
  defp validate_share_scope(%Document{doc_type: "folder"}, "folder"), do: :ok
  defp validate_share_scope(%Document{}, _scope), do: {:error, {:invalid_value, :scope}}

  defp validate_active_share_root(%Document{archived_at: nil}), do: :ok
  defp validate_active_share_root(%Document{}), do: {:error, {:invalid_value, :document_id}}

  defp fetch_token_prefix(attrs, share_slug) do
    expected = String.slice(share_slug, 0, 4)

    case Map.get(attrs, :token_prefix) || Map.get(attrs, "token_prefix") do
      ^expected -> {:ok, expected}
      _ -> {:error, :invalid_token_prefix}
    end
  end

  defp validate_password_share_fields(false, nil, nil, nil), do: :ok

  defp validate_password_share_fields(false, _salt, _kdf_params, _auth_key),
    do: {:error, {:invalid_value, :password_protected}}

  defp validate_password_share_fields(true, salt, kdf_params, auth_key) do
    cond do
      not is_binary(salt) or byte_size(salt) != 16 ->
        {:error, {:missing_field, :salt}}

      not is_map(kdf_params) ->
        {:error, {:missing_field, :kdf_params}}

      not valid_share_kdf_params?(kdf_params) ->
        {:error, :invalid_kdf_params}

      not is_binary(auth_key) or byte_size(auth_key) != 32 ->
        {:error, :invalid_auth_key}

      true ->
        :ok
    end
  end

  defp validate_encrypted_dek(encrypted_dek, false) when byte_size(encrypted_dek) == 32, do: :ok
  defp validate_encrypted_dek(encrypted_dek, true) when byte_size(encrypted_dek) == 48, do: :ok

  defp validate_encrypted_dek(_encrypted_dek, _password_protected),
    do: {:error, :invalid_encrypted_dek}

  defp validate_share_key_nonce(nil), do: :ok
  defp validate_share_key_nonce(nonce) when byte_size(nonce) == 24, do: :ok
  defp validate_share_key_nonce(_nonce), do: {:error, :invalid_nonce}

  defp validate_share_key_nonce(nil, false), do: :ok
  defp validate_share_key_nonce(_nonce, false), do: {:error, :invalid_nonce}
  defp validate_share_key_nonce(nil, true), do: {:error, :invalid_nonce}
  defp validate_share_key_nonce(nonce, true), do: validate_share_key_nonce(nonce)

  defp valid_share_kdf_params?(%{
         "algorithm" => "argon2id",
         "memory" => memory,
         "iterations" => iterations,
         "parallelism" => parallelism,
         "hash_length" => hash_length
       })
       when is_integer(memory) and is_integer(iterations) and is_integer(parallelism) and
              is_integer(hash_length) do
    integer_in_range?(memory, 16_384, 262_144) and
      integer_in_range?(iterations, 2, 10) and
      integer_in_range?(parallelism, 1, 8) and
      hash_length == 32
  end

  defp valid_share_kdf_params?(_), do: false

  defp integer_in_range?(value, min, max), do: value >= min and value <= max

  defp fetch_url_token(attrs, key) do
    token =
      case Map.get(attrs, key) do
        nil -> Map.get(attrs, to_string(key))
        value -> value
      end

    validate_url_token(token)
  end

  defp validate_url_token(token) when is_binary(token) do
    case Base.url_decode64(token, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 16 -> {:ok, token, bytes}
      _ -> {:error, :invalid_token}
    end
  end

  defp validate_url_token(_token), do: {:error, :invalid_token}

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
    with :ok <- validate_encrypted_dek(share_key.encrypted_dek, root_share.password_protected),
         :ok <- validate_share_key_nonce(share_key.nonce, root_share.password_protected) do
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

  defp random_manage_token_hash do
    {_token, token_bytes} = generate_url_token()
    Blake3.hash_base64url(token_bytes)
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
