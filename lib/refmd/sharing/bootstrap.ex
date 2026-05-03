defmodule RefMD.Sharing.Bootstrap do
  @moduledoc """
  Public share landing and participant bootstrap operations.
  """

  import Ecto.Query

  alias RefMD.Crypto
  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Workspaces

  alias RefMD.Sharing.{
    Access,
    Participants,
    ReadModels,
    ServerEnvelope,
    Share,
    ShareParticipantSession
  }

  @spec get_share_landing(String.t()) ::
          {:ok, %{share: Share.t(), root: map()}}
          | {:error, :not_found | :invalid_slug}
  def get_share_landing(share_slug) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         %Share{} = share <- find_active_share_by_hash(Blake3.hash_base64url(share_slug_bytes)),
         true <- share_links_enabled?(share),
         {:ok, root} <- get_share_root(share) do
      {:ok, %{share: share, root: root}}
    else
      {:error, :invalid_token} -> {:error, :invalid_slug}
      {:error, :not_found} -> {:error, :not_found}
      nil -> {:error, :not_found}
      false -> {:error, :not_found}
    end
  end

  @spec bootstrap_participant(String.t(), map()) ::
          {:ok,
           %{
             root: map(),
             participant: %{
               principal_id: Ecto.UUID.t(),
               device_id: Ecto.UUID.t(),
               grant: String.t()
             },
             session_token: binary()
           }}
          | {:error, term()}
  def bootstrap_participant(share_slug, attrs) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         {:ok, display_name} <- fetch_display_name(attrs),
         {:ok, signing_key} <- fetch_binary(attrs, :device_signing_pub_key),
         {:ok, encryption_key} <- fetch_binary(attrs, :device_encryption_pub_key),
         :ok <- validate_signing_key(signing_key),
         :ok <- validate_encryption_key(encryption_key) do
      bootstrap_participant_tx(share_slug_bytes, display_name, signing_key, encryption_key)
    end
  end

  @spec get_document_bootstrap(String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, :not_found}
  def get_document_bootstrap(document_token, session_token_base64) do
    with %{
           access_share: access_share,
           share: token_share,
           share_key: share_key,
           token: token,
           document: document
         } <-
           ReadModels.find_document_token_payload(document_token),
         true <- share_links_enabled?(access_share),
         true <- Access.document_accessible_in_share?(access_share, token.document_id),
         {:ok, share_slug} <- restore_share_slug(access_share) do
      build_document_bootstrap_response(
        access_share,
        token_share,
        share_key,
        token,
        document,
        session_token_base64,
        share_slug
      )
    else
      {:error, :invalid_share_slug} -> {:error, :not_found}
      _ -> {:error, :not_found}
    end
  end

  @spec get_folder_bootstrap(String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, :not_found}
  def get_folder_bootstrap(folder_token, session_token_base64) do
    with %{access_share: access_share, share: token_share, token: token} <-
           ReadModels.find_folder_token_payload(folder_token),
         true <- share_links_enabled?(access_share),
         true <- Access.folder_token_accessible_in_share?(access_share, token_share, token),
         {:ok, share_slug} <- restore_share_slug(access_share) do
      build_folder_bootstrap_result(
        access_share,
        token_share,
        token,
        session_token_base64,
        share_slug
      )
    else
      {:error, :invalid_share_slug} -> {:error, :not_found}
      _ -> {:error, :not_found}
    end
  end

  defp bootstrap_participant_tx(share_slug_bytes, display_name, signing_key, encryption_key) do
    Repo.transaction(fn ->
      share =
        from(s in Share,
          where:
            s.token_hash == ^Blake3.hash_base64url(share_slug_bytes) and
              is_nil(s.parent_share_id),
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      cond do
        share == nil ->
          Repo.rollback(:not_found)

        not share_links_enabled?(share) ->
          Repo.rollback(:not_found)

        not Access.share_accepting_participants?(share) ->
          Repo.rollback(:not_found)

        share.password_protected ->
          Repo.rollback(:password_required)

        true ->
          Participants.create_participant_session(
            share,
            display_name,
            signing_key,
            encryption_key
          )
      end
    end)
    |> normalize_transaction_result()
  end

  defp share_links_enabled?(share) do
    from(d in Document, where: d.id == ^share.document_id, select: d.workspace_id)
    |> Repo.one()
    |> case do
      workspace_id when is_binary(workspace_id) -> Workspaces.share_links_enabled?(workspace_id)
      _ -> false
    end
  end

  defp build_document_bootstrap_response(
         access_share,
         token_share,
         share_key,
         token,
         document,
         session_token_base64,
         share_slug
       ) do
    case Participants.get_valid_participant_session_by_token_base64(session_token_base64) do
      {:ok, %ShareParticipantSession{share_id: share_id} = session} ->
        handle_document_bootstrap_for_session(
          access_share,
          token_share,
          share_key,
          token,
          document,
          session,
          share_id,
          share_slug
        )

      _ ->
        if Access.share_accepting_participants?(access_share) do
          {:ok, bootstrap_required_response(share_slug)}
        else
          {:error, :not_found}
        end
    end
  end

  defp bootstrap_required_response(share_slug) do
    %{
      share_slug: share_slug,
      bootstrap_required: true
    }
  end

  defp handle_document_bootstrap_for_session(
         access_share,
         token_share,
         share_key,
         token,
         document,
         session,
         session_share_id,
         share_slug
       ) do
    cond do
      session_share_id != access_share.id ->
        mismatch_bootstrap_response(access_share, share_slug)

      not Participants.participant_owns_device?(session.principal_id, session.device_id) ->
        {:ok, bootstrap_required_response(share_slug)}

      not Access.document_accessible_in_share?(access_share, token.document_id) ->
        {:error, :not_found}

      Access.share_session_accessible_now?(access_share.id) ->
        ReadModels.authorized_document_bootstrap(
          access_share,
          token_share,
          share_key,
          token,
          document,
          session.grant,
          share_slug
        )

      true ->
        {:error, :not_found}
    end
  end

  defp build_folder_bootstrap_result(
         access_share,
         _token_share,
         _token,
         _session_token_base64,
         _share_slug
       )
       when not is_struct(access_share, Share),
       do: {:error, :not_found}

  defp build_folder_bootstrap_result(
         %Share{} = access_share,
         %Share{} = token_share,
         token,
         session_token_base64,
         share_slug
       ) do
    folder_bootstrap_for_session(
      access_share,
      token_share,
      token,
      session_token_base64,
      share_slug
    )
  end

  defp folder_bootstrap_for_session(
         %Share{} = access_share,
         %Share{} = token_share,
         token,
         session_token_base64,
         share_slug
       ) do
    case Participants.get_valid_participant_session_by_token_base64(session_token_base64) do
      {:ok, %ShareParticipantSession{share_id: share_id} = session} ->
        handle_folder_bootstrap_for_session(
          access_share,
          token_share,
          token,
          session,
          share_id,
          share_slug
        )

      _ ->
        if Access.share_accepting_participants?(access_share) do
          {:ok, bootstrap_required_response(share_slug)}
        else
          {:error, :not_found}
        end
    end
  end

  defp handle_folder_bootstrap_for_session(
         access_share,
         token_share,
         token,
         session,
         session_share_id,
         share_slug
       ) do
    cond do
      session_share_id != access_share.id ->
        mismatch_bootstrap_response(access_share, share_slug)

      not Participants.participant_owns_device?(session.principal_id, session.device_id) ->
        {:ok, bootstrap_required_response(share_slug)}

      Access.share_session_accessible_now?(access_share.id) ->
        ReadModels.build_authorized_folder_bootstrap(access_share, token_share, token, share_slug)

      true ->
        {:error, :not_found}
    end
  end

  defp mismatch_bootstrap_response(share, share_slug) do
    if Access.share_accepting_participants?(share) do
      {:ok, bootstrap_required_response(share_slug)}
    else
      {:error, :not_found}
    end
  end

  defp get_share_root(%Share{scope: "document"} = share) do
    case ReadModels.get_root_document_token(share.id, share.document_id) do
      %RefMD.Sharing.SharedDocumentToken{} = token ->
        {:ok, %{kind: "document", document_token: token.token}}

      nil ->
        {:error, :not_found}
    end
  end

  defp get_share_root(%Share{scope: "folder"} = share) do
    case ReadModels.get_root_folder_token(share.id, share.document_id) do
      %RefMD.Sharing.SharedFolderToken{} = token ->
        {:ok, %{kind: "folder", folder_token: token.token}}

      nil ->
        {:error, :not_found}
    end
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

  defp restore_share_slug(%Share{} = share) do
    case ServerEnvelope.decrypt_share_slug(
           share.slug_ciphertext,
           share.slug_nonce,
           share.slug_key_id,
           share.id
         ) do
      {:ok, share_slug_bytes} ->
        {:ok, Base.url_encode64(share_slug_bytes, padding: false)}

      _ ->
        {:error, :invalid_share_slug}
    end
  end

  defp fetch_display_name(attrs) do
    case Map.get(attrs, :display_name) || Map.get(attrs, "display_name") do
      value when is_binary(value) ->
        trimmed = String.trim(value)
        if trimmed == "", do: {:error, :invalid_display_name}, else: {:ok, trimmed}

      _ ->
        {:error, :invalid_display_name}
    end
  end

  defp fetch_binary(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  defp validate_signing_key(key) do
    cond do
      byte_size(key) != 32 ->
        {:error, {:invalid_key_size, :device_signing_pub_key}}

      not Crypto.valid_ed25519_public_key?(key) ->
        {:error, {:invalid_public_key, :device_signing_pub_key}}

      true ->
        :ok
    end
  end

  defp validate_encryption_key(key) do
    cond do
      byte_size(key) != 32 ->
        {:error, {:invalid_key_size, :device_encryption_pub_key}}

      not Crypto.valid_x25519_public_key?(key) ->
        {:error, {:invalid_public_key, :device_encryption_pub_key}}

      true ->
        :ok
    end
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
