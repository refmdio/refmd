defmodule RefMD.Sharing.Mounts do
  @moduledoc """
  Share mount operations.
  """

  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.Document
  alias RefMD.Documents.TreeOrdering
  alias RefMD.Repo
  alias RefMD.Workspaces

  alias RefMD.Sharing.{
    Access,
    PasswordChallenges,
    ReadModels,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareKey,
    ShareMount,
    SharePasswordChallenge
  }

  @spec create_share_mount(Ecto.UUID.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_share_mount(user_id, attrs) when is_binary(user_id) and is_map(attrs) do
    with {:ok, workspace_id} <- fetch_uuid(attrs, :workspace_id),
         {:ok, _share_slug, share_slug_bytes} <- fetch_url_token(attrs, :share_slug),
         {:ok, target_kind} <- fetch_enum(attrs, :target_kind, ~w(document folder)),
         {:ok, target_token} <- fetch_mount_target_token(attrs),
         {:ok, parent_id} <- fetch_optional_uuid(attrs, :parent_id) do
      Repo.transaction(fn ->
        create_share_mount_tx(user_id, %{
          workspace_id: workspace_id,
          share_slug_bytes: share_slug_bytes,
          target_kind: target_kind,
          target_token: target_token,
          parent_id: parent_id
        })
      end)
      |> normalize_transaction_result()
    end
  end

  @spec list_share_mounts_for_share(Ecto.UUID.t(), String.t()) ::
          {:ok, %{mounts: [map()]}} | {:error, term()}
  def list_share_mounts_for_share(user_id, share_slug) when is_binary(user_id) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         %Share{} = share <- find_active_share_by_hash(Blake3.hash_base64url(share_slug_bytes)) do
      mounts =
        from(m in ShareMount,
          where: m.user_id == ^user_id and m.share_id == ^share.id,
          order_by: [asc: m.created_at]
        )
        |> Repo.all()
        |> Enum.map(&serialize_share_mount_for_share/1)
        |> Enum.reject(&is_nil/1)

      {:ok, %{mounts: mounts}}
    else
      {:error, :invalid_token} -> {:error, :not_found}
      nil -> {:error, :not_found}
    end
  end

  @spec list_share_mounts(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{mounts: [map()]}} | {:error, term()}
  def list_share_mounts(user_id, workspace_id)
      when is_binary(user_id) and is_binary(workspace_id) do
    with :ok <- validate_workspace_member(workspace_id, user_id) do
      mounts =
        from(m in ShareMount,
          join: s in Share,
          on: s.id == m.share_id,
          join: d in Document,
          on: d.id == m.target_document_id,
          where: m.user_id == ^user_id and m.workspace_id == ^workspace_id,
          order_by: [asc: m.parent_id, asc: m.position, asc: m.id],
          select: {m, s, d}
        )
        |> Repo.all()
        |> Enum.map(fn {mount, share, target} -> serialize_share_mount(mount, share, target) end)

      {:ok, %{mounts: mounts}}
    end
  end

  @spec get_share_mount(Ecto.UUID.t(), Ecto.UUID.t()) :: {:ok, map()} | {:error, term()}
  def get_share_mount(user_id, mount_id) when is_binary(user_id) and is_binary(mount_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
           :active <- share_status(share) do
        maybe_increment_mount_access!(share)
        build_share_mount_detail(mount, share, target)
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec get_share_mount_document(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, term()}
  def get_share_mount_document(user_id, mount_id, document_id)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(document_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
           :active <- share_status(share),
           false <- share.password_protected,
           true <- mount_target_contains_document?(mount.target_document_id, document_id),
           true <- Access.can_read_document?(share.id, document_id) do
        maybe_increment_mount_access!(share)

        %{
          mount: serialize_share_mount(mount, share, target),
          admission: build_mount_document_admission!(share, document_id),
          folder_tree: nil,
          child_shares: nil
        }
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec get_share_mount_share(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, term()}
  def get_share_mount_share(user_id, mount_id, share_id)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(share_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
           :active <- share_status(share),
           false <- share.password_protected,
           {:ok, document_id} <- mounted_document_id_for_share(share, share_id),
           true <- mount_target_contains_document?(mount.target_document_id, document_id) do
        maybe_increment_mount_access!(share)

        %{
          mount: serialize_share_mount(mount, share, target),
          admission: build_mount_document_admission!(share, document_id),
          folder_tree: nil,
          child_shares: nil
        }
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec resolve_mounted_document_share(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Ecto.UUID.t()} | {:error, term()}
  def resolve_mounted_document_share(user_id, mount_id, document_id)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(document_id) do
    with {:ok, mount, share, _target} <- fetch_owned_mount_payload(user_id, mount_id, false),
         :active <- share_status(share),
         true <- mount_target_contains_document?(mount.target_document_id, document_id),
         true <- Access.can_read_document?(share.id, document_id) do
      {:ok, share.id}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :not_found}
    end
  end

  @spec update_share_mount(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, term()}
  def update_share_mount(user_id, mount_id, attrs)
      when is_binary(user_id) and is_binary(mount_id) and is_map(attrs) do
    with {:ok, parent_id} <- fetch_optional_uuid(attrs, :parent_id),
         {:ok, position} <- fetch_mount_position(attrs) do
      Repo.transaction(fn ->
        update_share_mount_tx(user_id, mount_id, parent_id, position)
      end)
      |> normalize_transaction_result()
    end
  end

  @spec delete_share_mount(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  def delete_share_mount(user_id, mount_id) when is_binary(user_id) and is_binary(mount_id) do
    Repo.transaction(fn -> delete_share_mount_tx(user_id, mount_id) end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @spec get_share_mount_folder(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def get_share_mount_folder(user_id, mount_id, folder_token)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(folder_token) do
    with {:ok, mount, share, _target} <- fetch_owned_mount_payload(user_id, mount_id, false),
         :active <- share_status(share),
         {:ok, folder_payload} <- build_mount_folder_payload(mount, share, folder_token) do
      {:ok, folder_payload}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :not_found}
    end
  end

  @spec get_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{challenge: binary(), salt: binary(), kdf_params: map()}} | {:error, term()}
  def get_share_mount_challenge(user_id, mount_id)
      when is_binary(user_id) and is_binary(mount_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, _target} <- fetch_owned_mount_payload(user_id, mount_id, true),
           :active <- share_status(share),
           true <- share.password_protected,
           %ShareKey{} = share_key <- Repo.get(ShareKey, share.id) do
        now = DateTime.utc_now()

        challenge =
          PasswordChallenges.insert_password_challenge!(
            PasswordChallenges.mount_password_challenge_hash(mount.id),
            share.id,
            now
          )

        %{
          challenge: challenge.challenge,
          salt: share_key.salt,
          kdf_params: share_key.kdf_params
        }
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec respond_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t(), binary()) ::
          {:ok, map()} | {:error, term()}
  def respond_share_mount_challenge(user_id, mount_id, response)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(response) do
    respond_share_mount_challenge(user_id, mount_id, response, nil)
  end

  @spec respond_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t(), binary(), Ecto.UUID.t() | nil) ::
          {:ok, map()} | {:error, term()}
  def respond_share_mount_challenge(user_id, mount_id, response, target_id)
      when is_binary(user_id) and is_binary(mount_id) and is_binary(response) do
    Repo.transaction(fn ->
      respond_share_mount_challenge_tx(user_id, mount_id, response, target_id)
    end)
    |> normalize_transaction_result()
  end

  defp create_share_mount_tx(user_id, attrs) do
    with :ok <- validate_workspace_member(attrs.workspace_id, user_id),
         :ok <- validate_mount_parent(attrs.workspace_id, attrs.parent_id),
         %Share{} = share <-
           fetch_active_share_for_mount!(Blake3.hash_base64url(attrs.share_slug_bytes)),
         {:ok, target} <- resolve_mount_target(share, attrs.target_kind, attrs.target_token) do
      position = TreeOrdering.count_combined_siblings(attrs.workspace_id, attrs.parent_id)

      mount_attrs = %{
        share_id: share.id,
        target_document_id: target.document.id,
        target_kind: attrs.target_kind,
        user_id: user_id,
        workspace_id: attrs.workspace_id,
        parent_id: attrs.parent_id,
        position: position
      }

      case %ShareMount{} |> ShareMount.changeset(mount_attrs) |> Repo.insert(mode: :savepoint) do
        {:ok, mount} ->
          TreeOrdering.normalize_combined_siblings!(mount.workspace_id, mount.parent_id)
          serialize_share_mount_result(mount, share, target.document, attrs.target_token)

        {:error, changeset} ->
          handle_share_mount_insert_error(changeset, user_id, share.id, target.document.id)
      end
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp fetch_active_share_for_mount!(token_hash) do
    from(s in Share,
      where: s.token_hash == ^token_hash and is_nil(s.parent_share_id),
      lock: "FOR UPDATE"
    )
    |> Repo.one()
    |> case do
      %Share{} = share ->
        if Access.share_accepting_participants?(share), do: share, else: Repo.rollback(:not_found)

      nil ->
        Repo.rollback(:not_found)
    end
  end

  defp handle_share_mount_insert_error(changeset, user_id, share_id, document_id) do
    if share_mount_unique_constraint_error?(changeset) do
      case get_existing_share_mount(user_id, share_id, document_id) do
        %ShareMount{} = mount ->
          Repo.rollback({:conflict, serialize_share_mount_for_conflict(mount)})

        nil ->
          Repo.rollback(changeset)
      end
    else
      Repo.rollback(changeset)
    end
  end

  defp update_share_mount_tx(user_id, mount_id, parent_id, position) do
    with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
         :ok <- validate_mount_parent(mount.workspace_id, parent_id) do
      TreeOrdering.move_share_mount!(mount, parent_id, position)

      mount = Repo.get!(ShareMount, mount.id)
      serialize_share_mount(mount, share, target)
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp delete_share_mount_tx(user_id, mount_id) do
    case fetch_owned_mount_payload(user_id, mount_id, true) do
      {:ok, mount, _share, _target} ->
        workspace_id = mount.workspace_id
        parent_id = mount.parent_id

        case Repo.delete(mount) do
          {:ok, _mount} ->
            TreeOrdering.normalize_combined_siblings!(workspace_id, parent_id)
            :ok

          {:error, changeset} ->
            Repo.rollback(changeset)
        end

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp respond_share_mount_challenge_tx(user_id, mount_id, response, target_id) do
    with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
         :active <- share_status(share),
         true <- share.password_protected,
         %SharePasswordChallenge{} = challenge <-
           from(c in SharePasswordChallenge,
             where: c.token_hash == ^PasswordChallenges.mount_password_challenge_hash(mount.id),
             where: c.expires_at > ^DateTime.utc_now(),
             lock: "FOR UPDATE"
           )
           |> Repo.one(),
         :ok <- PasswordChallenges.respond_share_challenge_record(challenge, share, response) do
      maybe_increment_mount_access!(share)
      build_share_mount_challenge_response(mount, share, target, target_id)
    else
      {:error, reason} -> Repo.rollback(reason)
      _ -> Repo.rollback(:not_found)
    end
  end

  defp build_share_mount_challenge_response(
         _mount,
         share,
         %Document{doc_type: "document"} = target,
         nil
       ) do
    %{
      admission: build_mount_document_admission!(share, target.id)
    }
  end

  defp build_share_mount_challenge_response(mount, share, _target, target_id)
       when is_binary(target_id) do
    with {:ok, document_id} <- mounted_target_document_id(share, target_id),
         true <- mount_target_contains_document?(mount.target_document_id, document_id),
         true <- Access.can_read_document?(share.id, document_id) do
      %{
        admission: build_mount_document_admission!(share, document_id)
      }
    else
      _ -> Repo.rollback(:not_found)
    end
  end

  defp build_share_mount_challenge_response(mount, share, target, nil) do
    build_share_mount_detail(mount, share, target, allow_protected_folder_tree: true)
  end

  defp mounted_target_document_id(%Share{} = share, target_id) do
    case mounted_document_id_for_share(share, target_id) do
      {:ok, document_id} -> {:ok, document_id}
      {:error, :not_found} -> {:ok, target_id}
    end
  end

  defp mounted_document_id_for_share(
         %Share{id: share_id, scope: "document", document_id: document_id},
         share_id
       ),
       do: {:ok, document_id}

  defp mounted_document_id_for_share(%Share{id: root_share_id, scope: "folder"}, share_id) do
    document_id =
      from(s in Share,
        where: s.id == ^share_id,
        where: s.parent_share_id == ^root_share_id,
        where: s.scope == "document",
        select: s.document_id
      )
      |> Repo.one()

    case document_id do
      nil -> {:error, :not_found}
      document_id -> {:ok, document_id}
    end
  end

  defp mounted_document_id_for_share(_share, _share_id), do: {:error, :not_found}

  defp resolve_mount_target(%Share{scope: "document"} = share, "document", target_token) do
    with %SharedDocumentToken{} = token <-
           ReadModels.get_root_document_token(share.id, share.document_id),
         true <- token.token == target_token,
         %Document{doc_type: "document"} = document <- Repo.get(Document, share.document_id) do
      {:ok, %{document: document, token: token}}
    else
      _ -> {:error, :not_found}
    end
  end

  defp resolve_mount_target(%Share{scope: "document"}, _target_kind, _target_token),
    do: {:error, :not_found}

  defp resolve_mount_target(%Share{scope: "folder"} = share, "document", target_token) do
    with %{token: token, share: token_share, document: %Document{doc_type: "document"} = document} <-
           ReadModels.find_document_token_payload(target_token),
         true <- token_share.parent_share_id == share.id,
         true <- Access.document_accessible_in_share?(share, token.document_id) do
      {:ok, %{document: document, token: token}}
    else
      _ -> {:error, :not_found}
    end
  end

  defp resolve_mount_target(%Share{scope: "folder"} = share, "folder", target_token) do
    with %{token: token, share: token_share} <- ReadModels.find_folder_token_payload(target_token),
         %Document{doc_type: "folder"} = document <- Repo.get(Document, token.document_id),
         true <- Access.folder_token_accessible_in_share?(share, token_share, token),
         true <- mount_folder_target_within_root?(share, token.document_id) do
      {:ok, %{document: document, token: token}}
    else
      _ -> {:error, :not_found}
    end
  end

  defp mount_folder_target_within_root?(%Share{document_id: document_id}, document_id), do: true

  defp mount_folder_target_within_root?(%Share{} = share, document_id) do
    Access.document_accessible_in_share?(share, document_id) or
      Access.folder_token_document_accessible?(share, document_id)
  end

  defp target_token_for_mount(%Share{} = share, %Document{doc_type: "document", id: document_id}) do
    from(t in SharedDocumentToken,
      join: s in Share,
      on: s.id == t.share_id,
      where:
        t.document_id == ^document_id and
          (s.id == ^share.id or s.parent_share_id == ^share.id),
      select: t.token,
      limit: 1
    )
    |> Repo.one()
  end

  defp target_token_for_mount(%Share{} = share, %Document{doc_type: "folder", id: document_id}) do
    from(t in SharedFolderToken,
      join: s in Share,
      on: s.id == t.share_id,
      where:
        t.document_id == ^document_id and
          (s.id == ^share.id or s.parent_share_id == ^share.id),
      select: t.token,
      limit: 1
    )
    |> Repo.one()
  end

  defp build_mount_folder_payload(%ShareMount{} = mount, %Share{} = share, folder_token) do
    with %{token: token, share: token_share} <- ReadModels.find_folder_token_payload(folder_token),
         true <- Access.folder_token_accessible_in_share?(share, token_share, token),
         true <- mount_target_contains_document?(mount.target_document_id, token.document_id),
         {:ok, folder_bootstrap} <-
           ReadModels.build_authorized_folder_bootstrap(share, token_share, token, nil) do
      {:ok,
       %{
         mount: %{
           id: mount.id,
           share_id: share.id,
           status: "active"
         },
         folder: folder_bootstrap.folder,
         entries: filter_mount_folder_entries(folder_bootstrap.entries, mount.target_document_id)
       }}
    else
      _ -> {:error, :not_found}
    end
  end

  defp filter_mount_folder_entries(entries, target_document_id) do
    Enum.filter(entries, &mount_target_contains_document?(target_document_id, &1.id))
  end

  defp mount_target_contains_document?(document_id, document_id), do: true

  defp mount_target_contains_document?(target_document_id, document_id) do
    Access.descendant_of?(document_id, target_document_id)
  end

  defp find_active_share_by_hash(token_hash) do
    from(s in Share, where: s.token_hash == ^token_hash and is_nil(s.parent_share_id))
    |> Repo.one()
    |> case do
      %Share{} = share ->
        if Access.share_accepting_participants?(share), do: share, else: nil

      _ ->
        nil
    end
  end

  defp validate_workspace_member(workspace_id, user_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil -> {:error, :forbidden}
      {_member, _role} -> :ok
    end
  end

  defp validate_mount_parent(_workspace_id, nil), do: :ok

  defp validate_mount_parent(workspace_id, parent_id) do
    case Repo.get(Document, parent_id) do
      %Document{workspace_id: ^workspace_id, doc_type: "folder", archived_at: nil} -> :ok
      %Document{} -> {:error, {:invalid_value, :parent_id}}
      nil -> {:error, {:invalid_value, :parent_id}}
    end
  end

  defp fetch_owned_mount_payload(user_id, mount_id, lock?) do
    query =
      from(m in ShareMount,
        join: s in Share,
        on: s.id == m.share_id,
        join: d in Document,
        on: d.id == m.target_document_id,
        where: m.id == ^mount_id and m.user_id == ^user_id,
        select: {m, s, d}
      )

    query = if lock?, do: from(row in query, lock: "FOR UPDATE"), else: query

    case Repo.one(query) do
      {mount, share, target} -> {:ok, mount, share, target}
      nil -> {:error, :not_found}
    end
  end

  defp get_existing_share_mount(user_id, share_id, document_id) do
    from(m in ShareMount,
      where:
        m.user_id == ^user_id and m.share_id == ^share_id and
          m.target_document_id == ^document_id
    )
    |> Repo.one()
  end

  defp share_mount_unique_constraint_error?(%Ecto.Changeset{} = changeset) do
    Enum.any?(changeset.constraints, fn constraint ->
      constraint.constraint == "share_mounts_share_target_user_index"
    end)
  end

  defp share_status(%Share{} = share) do
    cond do
      Access.expired?(share) -> :expired
      Access.access_limit_reached?(share) -> :access_limit_reached
      true -> :active
    end
  end

  defp share_status_string(share), do: share |> share_status() |> Atom.to_string()

  defp maybe_increment_mount_access!(%Share{password_protected: true}), do: :ok
  defp maybe_increment_mount_access!(%Share{} = share), do: increment_access_count!(share)

  defp increment_access_count!(%Share{access_limit: nil} = share) do
    {updated, _rows} =
      from(s in Share,
        where: s.id == ^share.id,
        select: %{id: s.id}
      )
      |> Repo.update_all(inc: [access_count: 1])

    if updated == 1, do: :ok, else: Repo.rollback(:not_found)
  end

  defp increment_access_count!(%Share{} = share) do
    {updated, _rows} =
      from(s in Share,
        where: s.id == ^share.id and (is_nil(s.access_limit) or s.access_count < s.access_limit),
        select: %{id: s.id}
      )
      |> Repo.update_all(inc: [access_count: 1])

    if updated == 0 do
      Repo.rollback(:not_found)
    end

    :ok
  end

  defp serialize_share_mount_result(mount, share, target, target_token) do
    mount
    |> serialize_share_mount(share, target)
    |> Map.put(:target_token, target_token)
  end

  defp serialize_share_mount_for_share(%ShareMount{} = mount) do
    with %Share{} = share <- Repo.get(Share, mount.share_id),
         %Document{} = target <- Repo.get(Document, mount.target_document_id),
         target_token when is_binary(target_token) <- target_token_for_mount(share, target) do
      %{
        id: mount.id,
        workspace_id: mount.workspace_id,
        share_id: mount.share_id,
        target_kind: mount.target_kind,
        target_token: target_token
      }
    else
      _ -> nil
    end
  end

  defp serialize_share_mount_for_conflict(%ShareMount{} = mount) do
    share = Repo.get!(Share, mount.share_id)
    target = Repo.get!(Document, mount.target_document_id)

    %{
      mount: serialize_share_mount(mount, share, target)
    }
  end

  defp serialize_share_mount(%ShareMount{} = mount, %Share{} = share, %Document{} = target) do
    %{
      id: mount.id,
      workspace_id: mount.workspace_id,
      share_id: mount.share_id,
      target_kind: mount.target_kind,
      target_token: target_token_for_mount(share, target),
      target_document_id: mount.target_document_id,
      parent_id: mount.parent_id,
      position: mount.position,
      status: share_status_string(share),
      password_protected: share.password_protected,
      share: %{
        scope: share.scope,
        permission: share.permission,
        document_id: share.document_id
      },
      target: serialize_mount_target(target),
      title: target.title,
      title_state: mount_title_state(share)
    }
  end

  defp serialize_mount_target(%Document{} = target) do
    %{
      document_id: target.id,
      doc_type: target.doc_type,
      title: target.title,
      encrypted_title: target.encrypted_title,
      encrypted_title_nonce: target.encrypted_title_nonce,
      encrypted_title_key_version: target.encrypted_title_key_version
    }
  end

  defp mount_title_state(%Share{password_protected: true}), do: "password_required"
  defp mount_title_state(%Share{}), do: "resolved"

  defp build_share_mount_detail(
         %ShareMount{} = mount,
         %Share{} = share,
         %Document{} = target,
         opts \\ []
       ) do
    mount_summary = serialize_share_mount(mount, share, target)
    include_protected_folder_tree? = Keyword.get(opts, :allow_protected_folder_tree, false)

    cond do
      target.doc_type == "document" and not share.password_protected ->
        %{
          mount: mount_summary,
          admission: build_mount_document_admission!(share, target.id),
          folder_tree: nil,
          child_shares: nil
        }

      target.doc_type == "folder" and
          (not share.password_protected or include_protected_folder_tree?) ->
        with target_token when is_binary(target_token) <- mount_summary.target_token,
             {:ok, folder_payload} <- build_mount_folder_payload(mount, share, target_token) do
          %{
            mount: mount_summary,
            admission: nil,
            folder_tree: Map.take(folder_payload, [:folder, :entries]),
            child_shares: mount_child_shares(folder_payload.entries)
          }
        else
          _ -> Repo.rollback(:not_found)
        end

      true ->
        %{
          mount: mount_summary,
          admission: nil,
          folder_tree: nil,
          child_shares: nil
        }
    end
  end

  defp mount_child_shares(entries) do
    Enum.map(entries, fn entry ->
      %{
        share_id: entry.share_id,
        document_id: entry.id,
        doc_type: entry.doc_type,
        document_token: entry.document_token,
        folder_token: entry.folder_token
      }
    end)
  end

  defp build_mount_document_admission!(%Share{} = share, document_id) do
    token_payload =
      from(t in SharedDocumentToken,
        join: s in Share,
        on: s.id == t.share_id,
        join: sk in ShareKey,
        on: sk.share_id == s.id,
        join: d in Document,
        on: d.id == t.document_id,
        where: t.document_id == ^document_id,
        where: s.id == ^share.id or s.parent_share_id == ^share.id,
        select: %{token: t, share: s, share_key: sk, document: d},
        limit: 1
      )
      |> Repo.one()

    case token_payload do
      %{token: token, share: token_share, share_key: share_key, document: document} ->
        case ReadModels.authorized_document_bootstrap(
               share,
               token_share,
               share_key,
               token,
               document,
               share.permission,
               nil
             ) do
          {:ok, admission} -> Map.delete(admission, :share_slug)
          {:error, _reason} -> Repo.rollback(:not_found)
        end

      _ ->
        Repo.rollback(:not_found)
    end
  end

  defp fetch_mount_target_token(attrs) do
    case Map.get(attrs, :target_token) || Map.get(attrs, "target_token") do
      value when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, {:missing_field, :target_token}}
    end
  end

  defp fetch_mount_position(attrs) do
    case Map.get(attrs, :position) || Map.get(attrs, "position") do
      value when is_integer(value) and value >= 0 ->
        {:ok, value}

      value when is_binary(value) ->
        case Integer.parse(value) do
          {position, ""} when position >= 0 -> {:ok, position}
          _ -> {:error, {:invalid_value, :position}}
        end

      nil ->
        {:error, {:missing_field, :position}}

      _ ->
        {:error, {:invalid_value, :position}}
    end
  end

  defp fetch_uuid(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) ->
        parse_uuid_value(value, key)

      _ ->
        {:error, {:missing_field, key}}
    end
  end

  defp fetch_optional_uuid(attrs, key) do
    case Map.get(attrs, key) do
      nil -> Map.get(attrs, to_string(key))
      value -> value
    end
    |> case do
      nil -> {:ok, nil}
      value -> parse_uuid_value(value, key)
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

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
