defmodule RefMD.Sharing.Bootstrap do
  @moduledoc """
  Public share landing and participant bootstrap operations.
  """

  import Ecto.Query

  alias RefMD.Crypto
  alias RefMD.Crypto.{Blake3, HybridEncryptionMaterial, Signature}
  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Workspaces

  alias RefMD.Sharing.{
    Access,
    Ledger,
    Lookup,
    Participants,
    Share,
    ShareParticipantSession
  }

  alias RefMD.Sharing.Participants.Authorization

  @spec get_share_landing(String.t(), String.t() | nil) ::
          {:ok, %{share: Share.t(), root: map()}}
          | {:error, :not_found | :invalid_slug}
  def get_share_landing(share_slug, session_token_base64 \\ nil) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         %Share{} = share <-
           find_active_share_by_hash(
             Blake3.hash_base64url(share_slug_bytes),
             session_token_base64
           ),
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
         {:ok, device_id} <- fetch_device_id(attrs),
         {:ok, hybrid_signing_public_key_material} <-
           fetch_hybrid_signing_public_key_material(attrs, device_id),
         {:ok, hybrid_encryption_public_key_material} <-
           fetch_hybrid_encryption_public_key_material(attrs, device_id),
         {:ok, _x25519_public_key, _mlkem768_public_key} <-
           validate_hybrid_encryption_material(hybrid_encryption_public_key_material),
         {:ok, participant_principal_id} <- fetch_uuid(attrs, :share_participant_principal_id),
         {:ok, participant_session_id} <- fetch_uuid(attrs, :share_participant_session_id),
         {:ok, capability_authorization} <-
           fetch_share_capability_authorization(attrs),
         {:ok, participant_device_authorization} <-
           fetch_share_participant_device_authorization(attrs) do
      bootstrap_participant_tx(
        share_slug_bytes,
        %{
          display_name: display_name,
          device_id: device_id,
          share_participant_principal_id: participant_principal_id,
          share_participant_session_id: participant_session_id,
          hybrid_signing_public_key_material: hybrid_signing_public_key_material,
          hybrid_encryption_public_key_material: hybrid_encryption_public_key_material,
          share_capability_authorization: capability_authorization,
          share_participant_device_authorization: participant_device_authorization
        }
      )
    end
  end

  @type authenticated_pin_hash :: String.t() | nil

  @spec get_document_bootstrap(String.t(), String.t() | nil, authenticated_pin_hash()) ::
          {:ok, map()} | {:error, :not_found}
  def get_document_bootstrap(
        document_token,
        session_token_base64,
        authenticated_pin_hash
      ) do
    with %{
           access_share: access_share,
           share: token_share,
           share_key: share_key,
           token: token,
           document: document
         } <-
           Lookup.find_document_token_payload(document_token),
         true <- share_links_enabled?(access_share),
         true <- Access.document_accessible_in_share?(access_share, token.document_id) do
      build_document_bootstrap_response(%{
        access_share: access_share,
        token_share: token_share,
        share_key: share_key,
        token: token,
        document: document,
        session_token_base64: session_token_base64,
        share_token_hash: access_share.token_hash,
        authenticated_pin_hash: authenticated_pin_hash
      })
    else
      _ -> {:error, :not_found}
    end
  end

  @spec get_folder_bootstrap(String.t(), String.t() | nil, authenticated_pin_hash()) ::
          {:ok, map()} | {:error, :not_found}
  def get_folder_bootstrap(
        folder_token,
        session_token_base64,
        authenticated_pin_hash
      ) do
    with %{access_share: access_share, share: token_share, token: token} <-
           Lookup.find_folder_token_payload(folder_token),
         true <- share_links_enabled?(access_share),
         true <- Access.folder_token_accessible_in_share?(access_share, token_share, token) do
      build_folder_bootstrap_result(
        access_share,
        token_share,
        token,
        session_token_base64,
        access_share.token_hash,
        authenticated_pin_hash
      )
    else
      _ -> {:error, :not_found}
    end
  end

  defp bootstrap_participant_tx(share_slug_bytes, authorization) do
    Repo.transaction(fn ->
      share =
        from(s in Share,
          where:
            s.token_hash == ^Blake3.hash_base64url(share_slug_bytes) and
              is_nil(s.parent_share_id),
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      bootstrap_existing_or_new_participant!(share, authorization)
    end)
    |> normalize_transaction_result()
  end

  defp bootstrap_existing_or_new_participant!(nil, _authorization),
    do: Repo.rollback(:not_found)

  defp bootstrap_existing_or_new_participant!(%Share{} = share, authorization) do
    cond do
      not share_links_enabled?(share) ->
        Repo.rollback(:not_found)

      not Participants.share_accepting_new_participant?(share) ->
        Repo.rollback(:not_found)

      share.password_protected ->
        Repo.rollback(:password_required)

      true ->
        case Authorization.attach_verified(share, authorization) do
          {:ok, verified_authorization} ->
            Participants.create_participant_session(share, verified_authorization)

          {:error, reason} ->
            Repo.rollback(reason)
        end
    end
  end

  defp share_links_enabled?(share) do
    from(d in Document, where: d.id == ^share.document_id, select: d.workspace_id)
    |> Repo.one()
    |> case do
      workspace_id when is_binary(workspace_id) -> Workspaces.share_links_enabled?(workspace_id)
      _ -> false
    end
  end

  defp build_document_bootstrap_response(%{
         access_share: access_share,
         token_share: token_share,
         share_key: share_key,
         token: token,
         document: document,
         session_token_base64: session_token_base64,
         share_token_hash: share_token_hash,
         authenticated_pin_hash: authenticated_pin_hash
       }) do
    case Participants.get_valid_participant_session_by_token_base64(session_token_base64) do
      {:ok, %ShareParticipantSession{share_id: share_id} = session} ->
        handle_document_bootstrap_for_session(%{
          access_share: access_share,
          token_share: token_share,
          share_key: share_key,
          token: token,
          document: document,
          session: session,
          session_share_id: share_id,
          share_token_hash: share_token_hash,
          authenticated_pin_hash: authenticated_pin_hash
        })

      _ ->
        if Access.share_session_accessible?(access_share) do
          {:ok, bootstrap_required_response(share_token_hash)}
        else
          {:error, :not_found}
        end
    end
  end

  defp bootstrap_required_response(share_token_hash) do
    %{
      share_token_hash: share_token_hash,
      bootstrap_required: true
    }
  end

  defp handle_document_bootstrap_for_session(%{
         access_share: access_share,
         token_share: token_share,
         share_key: share_key,
         token: token,
         document: document,
         session: session,
         session_share_id: session_share_id,
         share_token_hash: share_token_hash,
         authenticated_pin_hash: authenticated_pin_hash
       }) do
    cond do
      session_share_id != access_share.id ->
        mismatch_bootstrap_response(access_share, share_token_hash)

      not Participants.participant_owns_device?(session.principal_id, session.device_id) ->
        {:ok, bootstrap_required_response(share_token_hash)}

      is_nil(authenticated_pin_hash) ->
        {:ok,
         document_route_metadata(access_share, token, document, session.grant, share_token_hash)}

      not valid_authenticated_pin_hash?(access_share, authenticated_pin_hash) ->
        {:ok, bootstrap_required_response(share_token_hash)}

      not Access.document_accessible_in_share?(access_share, token.document_id) ->
        {:error, :not_found}

      Access.share_session_accessible_now?(access_share.id) ->
        document_bootstrap_after_recorded_open(
          access_share,
          token_share,
          share_key,
          token,
          document,
          session,
          share_token_hash
        )

      true ->
        {:error, :not_found}
    end
  end

  defp document_bootstrap_after_recorded_open(
         access_share,
         token_share,
         share_key,
         token,
         document,
         session,
         share_token_hash
       ) do
    case Ledger.record_existing_open(
           access_share,
           "share_participant_device",
           session.device_id
         ) do
      :ok ->
        Lookup.authorized_document_bootstrap(
          access_share,
          token_share,
          share_key,
          token,
          document,
          session.grant,
          share_token_hash
        )

      {:error, _reason} ->
        {:error, :not_found}
    end
  end

  defp build_folder_bootstrap_result(
         access_share,
         _token_share,
         _token,
         _session_token_base64,
         _share_token_hash,
         _authenticated_pin_hash
       )
       when not is_struct(access_share, Share),
       do: {:error, :not_found}

  defp build_folder_bootstrap_result(
         %Share{} = access_share,
         %Share{} = token_share,
         token,
         session_token_base64,
         share_token_hash,
         authenticated_pin_hash
       ) do
    folder_bootstrap_for_session(
      access_share,
      token_share,
      token,
      session_token_base64,
      share_token_hash,
      authenticated_pin_hash
    )
  end

  defp folder_bootstrap_for_session(
         %Share{} = access_share,
         %Share{} = token_share,
         token,
         session_token_base64,
         share_token_hash,
         authenticated_pin_hash
       ) do
    case Participants.get_valid_participant_session_by_token_base64(session_token_base64) do
      {:ok, %ShareParticipantSession{share_id: share_id} = session} ->
        handle_folder_bootstrap_for_session(
          access_share,
          token_share,
          token,
          session,
          share_id,
          share_token_hash,
          authenticated_pin_hash
        )

      _ ->
        if Access.share_session_accessible?(access_share) do
          {:ok, bootstrap_required_response(share_token_hash)}
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
         share_token_hash,
         authenticated_pin_hash
       ) do
    cond do
      session_share_id != access_share.id ->
        mismatch_bootstrap_response(access_share, share_token_hash)

      not Participants.participant_owns_device?(session.principal_id, session.device_id) ->
        {:ok, bootstrap_required_response(share_token_hash)}

      is_nil(authenticated_pin_hash) ->
        {:ok, folder_route_metadata(access_share, token, session.grant, share_token_hash)}

      not valid_authenticated_pin_hash?(access_share, authenticated_pin_hash) ->
        {:ok, bootstrap_required_response(share_token_hash)}

      Access.share_session_accessible_now?(access_share.id) ->
        folder_bootstrap_after_recorded_open(
          access_share,
          token_share,
          token,
          session,
          share_token_hash
        )

      true ->
        {:error, :not_found}
    end
  end

  defp folder_bootstrap_after_recorded_open(
         access_share,
         token_share,
         token,
         session,
         share_token_hash
       ) do
    case Ledger.record_existing_open(
           access_share,
           "share_participant_device",
           session.device_id
         ) do
      :ok ->
        Lookup.build_authorized_folder_bootstrap(
          access_share,
          token_share,
          token,
          session.grant,
          share_token_hash
        )

      {:error, _reason} ->
        {:error, :not_found}
    end
  end

  defp document_route_metadata(
         %Share{} = share,
         token,
         %Document{} = document,
         grant,
         share_token_hash
       ) do
    %{
      share_token_hash: share_token_hash,
      share_id: share.id,
      document_id: token.document_id,
      workspace_id: document.workspace_id,
      permission: grant,
      password_protected: share.password_protected,
      bootstrap_required: true
    }
  end

  defp folder_route_metadata(%Share{} = share, token, grant, share_token_hash) do
    %{
      share_token_hash: share_token_hash,
      share_id: share.id,
      folder_id: token.document_id,
      permission: grant,
      password_protected: share.password_protected,
      bootstrap_required: true
    }
  end

  defp mismatch_bootstrap_response(share, share_token_hash) do
    if Access.share_session_accessible?(share) do
      {:ok, bootstrap_required_response(share_token_hash)}
    else
      {:error, :not_found}
    end
  end

  defp valid_authenticated_pin_hash?(
         %Share{authenticated_workspace_pin_bootstrap_hash: expected},
         expected
       )
       when is_binary(expected),
       do: true

  defp valid_authenticated_pin_hash?(%Share{}, _), do: false

  defp get_share_root(%Share{scope: "document"} = share) do
    case Lookup.get_root_document_token(share.id, share.document_id) do
      %RefMD.Sharing.SharedDocumentToken{} = token ->
        {:ok, %{kind: "document", document_token: token.token}}

      nil ->
        {:error, :not_found}
    end
  end

  defp get_share_root(%Share{scope: "folder"} = share) do
    case Lookup.get_root_folder_token(share.id, share.document_id) do
      %RefMD.Sharing.SharedFolderToken{} = token ->
        {:ok, %{kind: "folder", folder_token: token.token}}

      nil ->
        {:error, :not_found}
    end
  end

  defp find_active_share_by_hash(token_hash, session_token_base64) do
    from(s in Share, where: s.token_hash == ^token_hash and is_nil(s.parent_share_id))
    |> Repo.one()
    |> case do
      %Share{} = share ->
        cond do
          Participants.share_accepting_new_participant?(share) ->
            share

          existing_participant_session?(share, session_token_base64) ->
            share

          true ->
            nil
        end

      _ ->
        nil
    end
  end

  defp existing_participant_session?(%Share{} = share, session_token_base64) do
    if Access.share_session_accessible?(share) do
      case Participants.get_valid_participant_session_by_token_base64(session_token_base64) do
        {:ok, %{share_id: share_id}} -> share_id == share.id
        _ -> false
      end
    else
      false
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

  defp fetch_device_id(attrs) do
    value =
      Map.get(attrs, :share_participant_device_id) ||
        Map.get(attrs, "share_participant_device_id")

    case Ecto.UUID.cast(value) do
      {:ok, device_id} -> {:ok, device_id}
      :error -> {:error, {:invalid_field, :share_participant_device_id}}
    end
  end

  defp fetch_uuid(attrs, field) do
    value = Map.get(attrs, field) || Map.get(attrs, to_string(field))

    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_field, field}}
    end
  end

  defp fetch_share_participant_device_authorization(attrs) do
    case Map.get(attrs, :share_participant_device_authorization) ||
           Map.get(attrs, "share_participant_device_authorization") do
      artifact when is_map(artifact) -> {:ok, artifact}
      _ -> {:error, {:missing_field, :share_participant_device_authorization}}
    end
  end

  defp fetch_share_capability_authorization(attrs) do
    case Map.get(attrs, :share_capability_authorization) ||
           Map.get(attrs, "share_capability_authorization") do
      artifact when is_map(artifact) -> {:ok, artifact}
      _ -> {:error, {:missing_field, :share_capability_authorization}}
    end
  end

  defp fetch_hybrid_signing_public_key_material(attrs, device_id) do
    material =
      Map.get(attrs, :hybrid_signing_public_key_material) ||
        Map.get(attrs, "hybrid_signing_public_key_material")

    Signature.assert_public_key_material!(material)

    cond do
      material["owner_kind"] != "share_participant_device" ->
        {:error, {:invalid_public_key, :hybrid_signing_public_key_material}}

      material["owner_id"] != device_id ->
        {:error, {:invalid_public_key, :hybrid_signing_public_key_material}}

      true ->
        {:ok, material}
    end
  rescue
    ArgumentError -> {:error, {:invalid_public_key, :hybrid_signing_public_key_material}}
  end

  defp fetch_hybrid_encryption_public_key_material(attrs, device_id) do
    material =
      Map.get(attrs, :hybrid_encryption_public_key_material) ||
        Map.get(attrs, "hybrid_encryption_public_key_material")

    HybridEncryptionMaterial.assert_public_key_material!(material)

    cond do
      material["owner_kind"] != "share_participant_device" ->
        {:error, {:invalid_public_key, :hybrid_encryption_public_key_material}}

      material["owner_id"] != device_id ->
        {:error, {:invalid_public_key, :hybrid_encryption_public_key_material}}

      true ->
        {:ok, material}
    end
  rescue
    ArgumentError ->
      {:error, {:invalid_public_key, :hybrid_encryption_public_key_material}}
  end

  defp validate_hybrid_encryption_material(material) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         x25519_public_key <- HybridEncryptionMaterial.x25519_public!(material),
         mlkem768_public_key <- HybridEncryptionMaterial.mlkem768_public!(material),
         true <- byte_size(x25519_public_key) == 32,
         true <- Crypto.valid_x25519_public_key?(x25519_public_key),
         true <- byte_size(mlkem768_public_key) == 1184 do
      {:ok, x25519_public_key, mlkem768_public_key}
    else
      _ -> {:error, {:invalid_public_key, :hybrid_encryption_public_key_material}}
    end
  rescue
    ArgumentError ->
      {:error, {:invalid_public_key, :hybrid_encryption_public_key_material}}
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
