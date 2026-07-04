defmodule RefMD.Sharing.Mounts do
  @moduledoc """
  Share mount operations.
  """

  import Ecto.Query
  import RefMD.Sharing.Mounts.Params

  alias RefMD.Crypto.Blake3
  alias RefMD.Devices
  alias RefMD.Documents
  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Workspaces

  alias RefMD.Sharing.{
    Access,
    Ledger,
    Lookup,
    Participants,
    PasswordChallenges,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareKey,
    ShareMount,
    ShareParticipantSession,
    SharePasswordChallenge
  }

  @spec create_share_mount(Ecto.UUID.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_share_mount(user_id, attrs) when is_binary(user_id) and is_map(attrs) do
    with {:ok, workspace_id} <- fetch_uuid(attrs, :workspace_id),
         {:ok, _share_slug, share_slug_bytes} <- fetch_url_token(attrs, :share_slug),
         {:ok, target_kind} <- fetch_enum(attrs, :target_kind, ~w(document folder)),
         {:ok, target_token} <- fetch_mount_target_token(attrs),
         {:ok, pin_hash} <- fetch_blake3_hash(attrs, :authenticated_workspace_pin_bootstrap_hash),
         {:ok, share_session_token} <- fetch_optional_binary(attrs, :__share_session_token),
         {:ok, parent_id} <- fetch_optional_uuid(attrs, :parent_id) do
      Repo.transaction(fn ->
        create_share_mount_tx(user_id, %{
          workspace_id: workspace_id,
          share_slug_bytes: share_slug_bytes,
          target_kind: target_kind,
          target_token: target_token,
          authenticated_workspace_pin_bootstrap_hash: pin_hash,
          share_session_token: share_session_token,
          parent_id: parent_id
        })
      end)
      |> normalize_transaction_result()
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

  @spec list_share_mounts_for_share(Ecto.UUID.t(), String.t()) ::
          {:ok, %{mounts: [map()]}} | {:error, term()}
  def list_share_mounts_for_share(user_id, share_slug)
      when is_binary(user_id) and is_binary(share_slug) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         %Share{} = share <-
           find_accessible_root_share(Blake3.hash_base64url(share_slug_bytes)) do
      mounts =
        from(m in ShareMount,
          join: d in Document,
          on: d.id == m.target_document_id,
          where: m.user_id == ^user_id and m.share_id == ^share.id,
          order_by: [asc: m.created_at],
          select: {m, d}
        )
        |> Repo.all()
        |> Enum.map(fn {mount, target} -> serialize_share_link_mount(mount, share, target) end)

      {:ok, %{mounts: mounts}}
    else
      {:error, :invalid_token} -> {:error, :not_found}
      nil -> {:error, :not_found}
    end
  end

  @spec get_share_mount(Ecto.UUID.t(), Ecto.UUID.t()) :: {:ok, map()} | {:error, term()}
  def get_share_mount(user_id, mount_id) when is_binary(user_id) and is_binary(mount_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, false),
           :active <- share_status(share) do
        build_share_mount_metadata(mount, share, target)
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec get_share_mount_document_by_token(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t(),
          Ecto.UUID.t(),
          map(),
          String.t() | nil,
          map() | nil
        ) ::
          {:ok, map()} | {:error, term()}
  def get_share_mount_document_by_token(
        user_id,
        mount_id,
        document_token,
        current_pop_device_id,
        mount_trust_anchor,
        session_token_base64 \\ nil,
        mount_password_session \\ nil
      )
      when is_binary(user_id) and is_binary(mount_id) and is_binary(document_token) and
             is_binary(current_pop_device_id) do
    Repo.transaction(fn ->
      with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
           :ok <- validate_mount_password_session(share, mount, user_id, mount_password_session),
           :ok <- validate_mount_pop_device(mount, user_id, current_pop_device_id),
           :ok <- validate_mount_trust_anchor(share, mount_trust_anchor),
           :active <- share_status(share),
           %{token: token, share: token_share} <-
             Lookup.find_document_token_payload(document_token),
           true <- token_share_belongs_to_mount_share?(share, token_share),
           true <- mount_target_contains_document?(mount.target_document_id, token.document_id),
           true <- Access.can_read_document?(share.id, token.document_id) do
        build_mount_document_detail(mount, share, target, token.document_id)
        |> put_in([:document, :document_token], document_token)
        |> maybe_refresh_mount_share_session(
          share,
          session_token_base64
        )
      else
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  @spec resolve_mounted_document_share_for_session(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Ecto.UUID.t()} | {:error, term()}
  def resolve_mounted_document_share_for_session(share_id, mount_id, document_id)
      when is_binary(share_id) and is_binary(mount_id) and is_binary(document_id) do
    resolve_mounted_document_share_for_session(share_id, mount_id, document_id, nil)
  end

  @spec resolve_mounted_document_share_for_session(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, Ecto.UUID.t()} | {:error, term()}
  def resolve_mounted_document_share_for_session(
        share_id,
        mount_id,
        document_id,
        requested_share_id
      ) do
    resolve_mounted_document_share_for_session(
      share_id,
      mount_id,
      document_id,
      requested_share_id,
      nil
    )
  end

  @spec resolve_mounted_document_share_for_session(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil,
          map() | nil
        ) ::
          {:ok, Ecto.UUID.t()} | {:error, term()}
  def resolve_mounted_document_share_for_session(
        share_id,
        mount_id,
        document_id,
        requested_share_id,
        mount_trust_anchor
      )
      when is_binary(share_id) and is_binary(mount_id) and is_binary(document_id) do
    with %ShareMount{} = mount <- Repo.get_by(ShareMount, id: mount_id, share_id: share_id),
         %Share{} = share <- Repo.get(Share, share_id),
         :ok <- validate_mount_trust_anchor(share, mount_trust_anchor),
         :active <- share_status(share),
         true <- mount_target_contains_document?(mount.target_document_id, document_id),
         {:ok, resolved_share_id} <-
           resolve_mounted_document_session_share(share, document_id, requested_share_id) do
      {:ok, resolved_share_id}
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

  @spec get_share_mount_folder(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t(),
          Ecto.UUID.t(),
          map(),
          String.t() | nil,
          map() | nil
        ) ::
          {:ok, map()} | {:error, term()}
  def get_share_mount_folder(
        user_id,
        mount_id,
        folder_token,
        current_pop_device_id,
        mount_trust_anchor,
        session_token_base64 \\ nil,
        mount_password_session \\ nil
      )
      when is_binary(user_id) and is_binary(mount_id) and is_binary(folder_token) and
             is_binary(current_pop_device_id) do
    with {:ok, mount, share, _target} <- fetch_owned_mount_payload(user_id, mount_id, false),
         :ok <- validate_mount_password_session(share, mount, user_id, mount_password_session),
         :ok <- validate_mount_pop_device(mount, user_id, current_pop_device_id),
         :ok <- validate_mount_trust_anchor(share, mount_trust_anchor),
         :active <- share_status(share),
         {:ok, folder_payload} <- build_mount_folder_payload(mount, share, folder_token) do
      {:ok,
       maybe_refresh_mount_share_session(
         folder_payload,
         share,
         session_token_base64
       )}
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

  @spec mount_challenge_rate_limit_share_id(Ecto.UUID.t()) :: Ecto.UUID.t() | nil
  def mount_challenge_rate_limit_share_id(mount_id) when is_binary(mount_id) do
    case Ecto.UUID.cast(mount_id) do
      {:ok, mount_id} ->
        from(m in ShareMount,
          join: s in Share,
          on: s.id == m.share_id,
          where: m.id == ^mount_id and is_nil(s.parent_share_id),
          select: s.id
        )
        |> Repo.one()

      :error ->
        nil
    end
  end

  @spec share_mount_children?(Ecto.UUID.t()) :: boolean()
  def share_mount_children?(document_id) when is_binary(document_id) do
    from(m in ShareMount, where: m.parent_id == ^document_id, limit: 1)
    |> Repo.exists?()
  end

  @spec respond_share_mount_challenge(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          binary(),
          Ecto.UUID.t() | nil,
          String.t(),
          String.t() | nil
        ) :: {:ok, map()} | {:error, term()}
  def respond_share_mount_challenge(
        user_id,
        mount_id,
        current_pop_device_id,
        response,
        target_id,
        password_challenge_hash,
        session_token_base64 \\ nil
      )
      when is_binary(user_id) and is_binary(mount_id) and is_binary(current_pop_device_id) and
             is_binary(response) and is_binary(password_challenge_hash) do
    Repo.transaction(fn ->
      respond_share_mount_challenge_tx(
        user_id,
        mount_id,
        current_pop_device_id,
        response,
        target_id,
        password_challenge_hash,
        session_token_base64
      )
    end)
    |> normalize_transaction_result()
  end

  defp create_share_mount_tx(user_id, attrs) do
    with :ok <- validate_workspace_member(attrs.workspace_id, user_id),
         :ok <- validate_mount_parent(attrs.workspace_id, attrs.parent_id),
         %Share{} = share <-
           fetch_active_share_for_mount!(Blake3.hash_base64url(attrs.share_slug_bytes)),
         :ok <- validate_mount_trust_anchor(share, attrs),
         {:ok, target} <- resolve_mount_target(share, attrs.target_kind, attrs.target_token) do
      position = Documents.count_combined_siblings(attrs.workspace_id, attrs.parent_id)

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
          maybe_increment_mount_admission_count!(share, mount.user_id, attrs.share_session_token)
          Documents.normalize_combined_siblings!(mount.workspace_id, mount.parent_id)
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
        if Access.share_session_accessible?(share) and share_links_enabled?(share),
          do: share,
          else: Repo.rollback(:not_found)

      nil ->
        Repo.rollback(:not_found)
    end
  end

  defp find_accessible_root_share(token_hash) do
    from(s in Share,
      where: s.token_hash == ^token_hash and is_nil(s.parent_share_id)
    )
    |> Repo.one()
    |> case do
      %Share{} = share ->
        if Access.share_session_accessible?(share) and share_links_enabled?(share), do: share

      nil ->
        nil
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
      Documents.move_share_mount!(mount, parent_id, position)

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
            Documents.normalize_combined_siblings!(workspace_id, parent_id)
            :ok

          {:error, changeset} ->
            Repo.rollback(changeset)
        end

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp respond_share_mount_challenge_tx(
         user_id,
         mount_id,
         current_pop_device_id,
         response,
         _target_id,
         password_challenge_hash,
         session_token_base64
       ) do
    with {:ok, mount, share, target} <- fetch_owned_mount_payload(user_id, mount_id, true),
         :ok <- validate_mount_pop_device(mount, user_id, current_pop_device_id),
         :active <- share_status(share),
         true <- share.password_protected,
         ^password_challenge_hash <- PasswordChallenges.mount_password_challenge_hash(mount.id),
         %SharePasswordChallenge{} = challenge <-
           from(c in SharePasswordChallenge,
             where: c.token_hash == ^password_challenge_hash,
             where: c.expires_at > ^DateTime.utc_now(),
             lock: "FOR UPDATE"
           )
           |> Repo.one(),
         :ok <- PasswordChallenges.respond_share_challenge_record(challenge, share, response) do
      mount
      |> build_share_mount_challenge_response(share, target)
      |> maybe_refresh_mount_share_session(share, session_token_base64)
    else
      {:error, reason} -> Repo.rollback(reason)
      _ -> Repo.rollback(:not_found)
    end
  end

  defp build_share_mount_challenge_response(mount, share, _target) do
    %{
      mount_id: mount.id,
      bootstrap_required: true,
      mount_password_session: %{mount_id: mount.id, share_id: share.id, user_id: mount.user_id}
    }
  end

  defp maybe_refresh_mount_share_session(
         response,
         %Share{} = share,
         session_token_base64
       )
       when is_binary(session_token_base64) do
    with {:ok, %ShareParticipantSession{share_id: share_id} = session} <-
           Participants.get_valid_participant_session_by_token_base64(session_token_base64),
         true <- token_share_belongs_to_mount_share?(share, %Share{id: share_id}),
         %{session_token: session_token} <-
           Participants.resume_participant_session(share, session, session_token_base64) do
      Map.put(response, :session_token, session_token)
    else
      _ -> maybe_refresh_mount_share_session(response, share, nil)
    end
  end

  defp maybe_refresh_mount_share_session(
         response,
         _share,
         _session_token_base64
       ),
       do: response

  defp validate_mount_pop_device(
         %ShareMount{user_id: user_id},
         user_id,
         current_pop_device_id
       )
       when is_binary(current_pop_device_id) do
    if Devices.user_owns_active_device?(user_id, current_pop_device_id),
      do: :ok,
      else: {:error, :not_found}
  end

  defp validate_mount_pop_device(%ShareMount{}, _user_id, _current_pop_device_id),
    do: {:error, :not_found}

  defp token_share_belongs_to_mount_share?(%Share{id: share_id}, %Share{id: share_id}), do: true

  defp token_share_belongs_to_mount_share?(%Share{id: share_id}, %Share{parent_share_id: share_id}),
       do: true

  defp token_share_belongs_to_mount_share?(_share, _token_share), do: false

  defp resolve_mounted_document_session_share(%Share{} = share, document_id, requested_share_id)
       when is_binary(requested_share_id) do
    with %Share{} = requested_share <- Repo.get(Share, requested_share_id),
         true <- token_share_belongs_to_mount_share?(share, requested_share),
         true <- requested_share.document_id == document_id,
         true <- Access.can_read_document?(requested_share.id, document_id) do
      {:ok, requested_share.id}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :not_found}
    end
  end

  defp resolve_mounted_document_session_share(%Share{} = share, document_id, _requested_share_id) do
    if Access.can_read_document?(share.id, document_id) do
      {:ok, share.id}
    else
      {:error, :not_found}
    end
  end

  defp resolve_mount_target(%Share{scope: "document"} = share, "document", target_token) do
    with %SharedDocumentToken{} = token <-
           Lookup.get_root_document_token(share.id, share.document_id),
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
           Lookup.find_document_token_payload(target_token),
         true <- token_share.parent_share_id == share.id,
         true <- Access.document_accessible_in_share?(share, token.document_id) do
      {:ok, %{document: document, token: token}}
    else
      _ -> {:error, :not_found}
    end
  end

  defp resolve_mount_target(%Share{scope: "folder"} = share, "folder", target_token) do
    with %{token: token, share: token_share} <- Lookup.find_folder_token_payload(target_token),
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
    with %{token: token, share: token_share} <- Lookup.find_folder_token_payload(folder_token),
         true <- Access.folder_token_accessible_in_share?(share, token_share, token),
         true <- mount_target_contains_document?(mount.target_document_id, token.document_id),
         {:ok, folder_bootstrap} <-
           Lookup.build_authorized_folder_bootstrap(
             share,
             token_share,
             token,
             share.permission,
             nil
           ) do
      {:ok,
       %{
         mount: %{
           id: mount.id,
           share_id: share.id,
           workspace_id: mount.workspace_id,
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

  defp validate_workspace_member(workspace_id, user_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil -> {:error, :forbidden}
      {_member, _role} -> :ok
    end
  end

  defp validate_mount_trust_anchor(
         %Share{
           authenticated_workspace_pin_bootstrap_hash: pin_hash
         },
         %{
           authenticated_workspace_pin_bootstrap_hash: pin_hash
         }
       ),
       do: :ok

  defp validate_mount_trust_anchor(%Share{}, _), do: {:error, :not_found}

  defp validate_mount_password_session(
         %Share{password_protected: false},
         _mount,
         _user_id,
         _session
       ),
       do: :ok

  defp validate_mount_password_session(
         %Share{id: share_id, password_protected: true},
         %ShareMount{id: mount_id},
         user_id,
         %{mount_id: mount_id, share_id: share_id, user_id: user_id}
       ),
       do: :ok

  defp validate_mount_password_session(
         %Share{password_protected: true},
         _mount,
         _user_id,
         _session
       ),
       do: {:error, :not_found}

  defp maybe_increment_mount_admission_count!(%Share{} = share, user_id, session_token) do
    case Participants.get_valid_participant_session_by_token_base64(session_token) do
      {:ok, %{share_id: share_id, grant: "view", device_id: device_id}}
      when share_id == share.id ->
        if Ledger.consumed?(share.id, "share_participant_device", device_id),
          do: :ok,
          else: Ledger.consume!(share, "share_mount_user", user_id)

      {:ok, %{share_id: share_id, grant: "edit", device_id: device_id}}
      when share_id == share.id ->
        if Ledger.consumed?(share.id, "share_participant_device", device_id),
          do: :ok,
          else: Ledger.consume!(share, "share_mount_user", user_id)

      _ ->
        Ledger.consume!(share, "share_mount_user", user_id)
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
      not share_links_enabled?(share) -> :expired
      true -> :active
    end
  end

  defp share_links_enabled?(%Share{} = share) do
    from(d in Document, where: d.id == ^share.document_id, select: d.workspace_id)
    |> Repo.one()
    |> case do
      workspace_id when is_binary(workspace_id) -> Workspaces.share_links_enabled?(workspace_id)
      _ -> false
    end
  end

  defp share_status_string(share), do: share |> share_status() |> Atom.to_string()

  defp serialize_share_mount_result(mount, share, target, _target_token),
    do: serialize_share_mount(mount, share, target)

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
      target: serialize_mount_target(share, target)
    }
  end

  defp serialize_share_link_mount(
         %ShareMount{} = mount,
         %Share{} = share,
         %Document{} = target
       ) do
    %{
      id: mount.id,
      workspace_id: mount.workspace_id,
      share_id: mount.share_id,
      target_kind: mount.target_kind,
      target_token: target_token_for_mount(share, target)
    }
  end

  defp serialize_mount_target(%Share{} = _share, %Document{} = target) do
    %{
      document_id: target.id,
      doc_type: target.doc_type
    }
  end

  defp build_share_mount_metadata(
         %ShareMount{} = mount,
         %Share{} = share,
         %Document{} = target
       ) do
    %{
      mount: serialize_share_mount(mount, share, target),
      bootstrap_required: true
    }
  end

  defp build_mount_document_detail(
         %ShareMount{} = mount,
         %Share{} = share,
         %Document{} = target,
         document_id
       ) do
    %{
      mount: serialize_share_mount(mount, share, target),
      document: build_mount_document_bootstrap!(share, document_id)
    }
  end

  defp build_mount_document_bootstrap!(%Share{} = share, document_id) do
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
        {:ok, admission} =
          Lookup.authorized_document_bootstrap(
            share,
            token_share,
            share_key,
            token,
            document,
            share.permission,
            nil
          )

        admission
        |> Map.take([
          :share_id,
          :authorization_share_id,
          :document_id,
          :workspace_id,
          :encrypted_title,
          :encrypted_title_nonce,
          :encrypted_title_key_version,
          :key_version,
          :permission,
          :password_protected,
          :encrypted_dek,
          :nonce,
          :workspace_pin_bootstrap,
          :workspace_key_directory_checkpoint,
          :workspace_key_directory_latest_checkpoint,
          :workspace_key_directory_checkpoint_ancestry,
          :workspace_key_directory_event_ancestry,
          :verification_directory
        ])
        |> Map.put(:document_token, token.token)

      _ ->
        Repo.rollback(:not_found)
    end
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
