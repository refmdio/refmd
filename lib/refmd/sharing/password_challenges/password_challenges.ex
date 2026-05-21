defmodule RefMD.Sharing.PasswordChallenges do
  @moduledoc """
  Password challenge support for share admission.
  """

  import Ecto.Query

  alias RefMD.Crypto
  alias RefMD.Crypto.{Blake3, HybridEncryptionMaterial, Signature}
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces

  alias RefMD.Sharing.{
    Participants,
    Share,
    ShareKey,
    SharePasswordChallenge
  }

  alias RefMD.Sharing.Participants.Authorization

  @share_password_challenge_ttl 5 * 60
  @share_target_kdf_params %{
    "algorithm" => "argon2id",
    "memory" => 65_536,
    "iterations" => 3,
    "parallelism" => 4,
    "hash_length" => 32
  }

  @spec get_password_challenge(String.t()) ::
          {:ok, %{challenge: binary(), salt: binary(), kdf_params: map()}} | {:error, term()}
  def get_password_challenge(share_slug) when is_binary(share_slug) do
    now = DateTime.utc_now()

    %{token_hash: token_hash, share_id: share_id, salt: salt, kdf_params: kdf_params} =
      resolve_password_challenge_target(share_slug)

    Repo.transaction(fn ->
      get_or_insert_password_challenge!(token_hash, share_id, now, salt, kdf_params)
    end)
    |> normalize_transaction_result()
  end

  @spec password_challenge_rate_limit_share_id(String.t()) :: Ecto.UUID.t() | nil
  def password_challenge_rate_limit_share_id(share_slug) when is_binary(share_slug) do
    case validate_url_token(share_slug) do
      {:ok, _share_slug, share_slug_bytes} ->
        token_hash = Blake3.hash_base64url(share_slug_bytes)

        from(s in Share,
          where: s.token_hash == ^token_hash and is_nil(s.parent_share_id),
          select: s.id
        )
        |> Repo.one()

      _ ->
        nil
    end
  end

  @spec delete_expired_password_challenges() :: {non_neg_integer(), nil}
  def delete_expired_password_challenges do
    now = DateTime.utc_now()

    from(c in SharePasswordChallenge, where: c.expires_at <= ^now)
    |> Repo.delete_all()
  end

  @spec respond_password_challenge(String.t(), map()) ::
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
  def respond_password_challenge(share_slug, attrs) when is_binary(share_slug) do
    with {:ok, response} <- fetch_binary(attrs, :response),
         :ok <- validate_hmac_response(response),
         {:ok, password_challenge_hash} <- fetch_binary(attrs, :password_challenge_hash),
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
      respond_password_challenge_tx(
        share_slug,
        response,
        password_challenge_hash,
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

  @spec mount_password_challenge_hash(Ecto.UUID.t()) :: String.t()
  def mount_password_challenge_hash(mount_id) do
    Blake3.hash_base64url("mount:" <> mount_id)
  end

  @spec insert_password_challenge!(String.t(), Ecto.UUID.t() | nil, DateTime.t()) ::
          SharePasswordChallenge.t() | no_return()
  def insert_password_challenge!(token_hash, share_id, now) do
    challenge = :crypto.strong_rand_bytes(32)
    expires_at = DateTime.add(now, @share_password_challenge_ttl, :second)

    params = %{
      share_id: share_id,
      token_hash: token_hash,
      challenge: challenge,
      expires_at: expires_at
    }

    case %SharePasswordChallenge{created_at: now}
         |> SharePasswordChallenge.changeset(params)
         |> Repo.insert(on_conflict: :nothing, conflict_target: [:token_hash]) do
      {:ok, %SharePasswordChallenge{id: id} = inserted} when not is_nil(id) ->
        inserted

      {:ok, %SharePasswordChallenge{id: nil}} ->
        from(c in SharePasswordChallenge,
          where: c.token_hash == ^token_hash and c.expires_at > ^now
        )
        |> Repo.one()
        |> case do
          %SharePasswordChallenge{} = active_challenge ->
            active_challenge

          nil ->
            Repo.rollback(:not_found)
        end

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  @spec respond_share_challenge_record(SharePasswordChallenge.t(), Share.t(), binary()) ::
          :ok | no_return()
  def respond_share_challenge_record(challenge_record, share, response) do
    Repo.delete!(challenge_record)

    share_key =
      from(sk in ShareKey,
        where: sk.share_id == ^share.id
      )
      |> Repo.one()

    case verify_password_challenge_share({share, share_key}, challenge_record.challenge, response) do
      {:ok, _share, _share_key} -> :ok
      {:error, reason, _challenge, _response} -> Repo.rollback(reason)
    end
  end

  defp respond_password_challenge_tx(share_slug, response, password_challenge_hash, authorization) do
    Repo.transaction(fn ->
      %{token_hash: token_hash} = resolve_password_challenge_target(share_slug)
      now = DateTime.utc_now()

      challenge =
        if password_challenge_hash == challenge_token_hash(share_slug) do
          from(c in SharePasswordChallenge,
            where: c.token_hash == ^token_hash and c.expires_at > ^now,
            lock: "FOR UPDATE"
          )
          |> Repo.one()
        end

      respond_password_challenge_record(
        challenge,
        response,
        authorization
      )
    end)
    |> normalize_transaction_result()
  end

  defp respond_password_challenge_record(
         nil,
         _response,
         _authorization
       ),
       do: Repo.rollback(:not_found)

  defp respond_password_challenge_record(
         %SharePasswordChallenge{share_id: nil} = challenge_record,
         response,
         _authorization
       ) do
    Repo.delete!(challenge_record)
    verify_dummy_password_response!(challenge_record.challenge, response)
  end

  defp respond_password_challenge_record(
         %SharePasswordChallenge{} = challenge_record,
         response,
         authorization
       ) do
    Repo.delete!(challenge_record)

    challenge_record
    |> fetch_password_challenge_share()
    |> verify_password_challenge_share(challenge_record.challenge, response, authorization)
    |> create_password_challenge_session(authorization)
  end

  defp get_or_insert_password_challenge!(token_hash, share_id, now, salt, kdf_params) do
    delete_expired_password_challenges!(token_hash, now)

    token_hash
    |> active_password_challenge(now)
    |> password_challenge_response(token_hash, share_id, now, salt, kdf_params)
  end

  defp delete_expired_password_challenges!(token_hash, now) do
    from(c in SharePasswordChallenge,
      where: c.token_hash == ^token_hash and c.expires_at <= ^now
    )
    |> Repo.delete_all()
  end

  defp active_password_challenge(token_hash, now) do
    from(c in SharePasswordChallenge,
      where: c.token_hash == ^token_hash and c.expires_at > ^now
    )
    |> Repo.one()
  end

  defp password_challenge_response(
         %SharePasswordChallenge{} = active_challenge,
         _token_hash,
         _share_id,
         _now,
         salt,
         kdf_params
       ) do
    %{challenge: active_challenge.challenge, salt: salt, kdf_params: kdf_params}
  end

  defp password_challenge_response(nil, token_hash, share_id, now, salt, kdf_params) do
    inserted = insert_password_challenge!(token_hash, share_id, now)
    %{challenge: inserted.challenge, salt: salt, kdf_params: kdf_params}
  end

  defp fetch_password_challenge_share(challenge_record) do
    share =
      from(s in Share,
        where: s.id == ^challenge_record.share_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    share_key =
      from(sk in ShareKey,
        where: sk.share_id == ^challenge_record.share_id
      )
      |> Repo.one()

    {share, share_key}
  end

  defp verify_password_challenge_share(
         payload,
         challenge,
         response
       ),
       do: verify_password_challenge_share(payload, challenge, response, nil)

  defp verify_password_challenge_share(
         {%Share{} = protected_share, %ShareKey{} = protected_key},
         challenge,
         response,
         _authorization
       ) do
    with true <- Participants.share_accepting_new_participant?(protected_share),
         true <- share_links_enabled?(protected_share),
         true <- protected_share.password_protected,
         :ok <- validate_password_challenge_response_shape(challenge, response),
         :ok <-
           verify_password_auth_key_response(
             protected_key,
             protected_share.id,
             challenge,
             response
           ) do
      {:ok, protected_share, protected_key}
    else
      _ -> {:error, :not_found, challenge, response}
    end
  end

  defp verify_password_challenge_share(_payload, challenge, response, _authorization),
    do: {:error, :not_found, challenge, response}

  defp create_password_challenge_session(
         {:ok, protected_share, _protected_key},
         authorization
       ) do
    case Authorization.attach_verified(protected_share, authorization) do
      {:ok, verified_authorization} ->
        Participants.create_participant_session(protected_share, verified_authorization)

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp create_password_challenge_session(
         {:error, :not_found, challenge, response},
         _authorization
       ),
       do: verify_dummy_password_response!(challenge, response)

  defp resolve_password_challenge_target(share_slug) do
    case find_password_protected_share_for_challenge(share_slug) do
      %{share: share, share_key: share_key} ->
        %{
          token_hash: challenge_token_hash(share_slug),
          share_id: share.id,
          salt: share_key.salt,
          kdf_params: share_key.kdf_params
        }

      _ ->
        %{
          token_hash: dummy_password_challenge_token_hash(share_slug),
          share_id: nil,
          salt: generate_dummy_share_salt(share_slug),
          kdf_params: @share_target_kdf_params
        }
    end
  end

  defp find_password_protected_share_for_challenge(share_slug) do
    with {:ok, _share_slug, share_slug_bytes} <- validate_url_token(share_slug),
         token_hash = Blake3.hash_base64url(share_slug_bytes),
         %Share{} = share <- find_active_share_by_hash(token_hash),
         true <- share_links_enabled?(share),
         true <- share.password_protected,
         %ShareKey{} = share_key <- Repo.get(ShareKey, share.id),
         true <- is_binary(share_key.salt),
         true <- is_map(share_key.kdf_params),
         true <- is_map(share.authorization_public_key_material) do
      %{share: share, share_key: share_key}
    else
      _ -> nil
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

  defp find_active_share_by_hash(token_hash) do
    from(s in Share, where: s.token_hash == ^token_hash and is_nil(s.parent_share_id))
    |> Repo.one()
    |> case do
      %Share{} = share ->
        if Participants.share_accepting_new_participant?(share), do: share, else: nil

      _ ->
        nil
    end
  end

  defp validate_password_challenge_response_shape(challenge, response)
       when is_binary(challenge) and byte_size(challenge) == 32 and
              is_binary(response) and byte_size(response) == 32,
       do: :ok

  defp validate_password_challenge_response_shape(_challenge, _response), do: {:error, :not_found}

  defp verify_password_auth_key_response(
         %ShareKey{
           encrypted_auth_key: encrypted_auth_key,
           auth_key_nonce: auth_key_nonce,
           auth_key_server_key_id: auth_key_server_key_id
         },
         share_id,
         challenge,
         response
       )
       when is_binary(encrypted_auth_key) and is_binary(auth_key_nonce) and
              is_binary(auth_key_server_key_id) do
    case Encryption.decrypt_share_auth_key(
           encrypted_auth_key,
           auth_key_nonce,
           auth_key_server_key_id,
           share_id
         ) do
      {:ok, auth_key} ->
        expected = :crypto.mac(:hmac, :sha256, auth_key, challenge)
        if :crypto.hash_equals(expected, response), do: :ok, else: {:error, :not_found}

      _ ->
        {:error, :not_found}
    end
  end

  defp verify_password_auth_key_response(_share_key, _share_id, _challenge, _response),
    do: {:error, :not_found}

  defp verify_dummy_password_response!(challenge, response) do
    expected = :crypto.mac(:hmac, :sha256, :crypto.strong_rand_bytes(32), challenge)
    _ = :crypto.hash_equals(expected, response)
    Repo.rollback(:not_found)
  end

  defp challenge_token_hash(share_slug) do
    case Base.url_decode64(share_slug, padding: false) do
      {:ok, share_slug_bytes} -> Blake3.hash_base64url(share_slug_bytes)
      :error -> Blake3.hash_base64url(share_slug)
    end
  end

  defp dummy_password_challenge_token_hash(share_slug) do
    Blake3.hash_base64url("__share_password_challenge_dummy__:" <> share_slug)
  end

  defp generate_dummy_share_salt(share_slug) do
    secret =
      case Application.get_env(:refmd, :dummy_salt_secret) do
        nil ->
          raise "DUMMY_SALT_SECRET is not configured. Set DUMMY_SALT_SECRET environment variable."

        value when is_binary(value) ->
          value
      end

    :crypto.mac(:hmac, :sha256, secret, share_slug)
    |> binary_part(0, 16)
  end

  defp fetch_binary(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  defp fetch_display_name(attrs) do
    case dual_key_get(attrs, :display_name) do
      value when is_binary(value) ->
        trimmed = String.trim(value)
        if trimmed == "", do: {:error, :invalid_display_name}, else: {:ok, trimmed}

      _ ->
        {:error, :invalid_display_name}
    end
  end

  defp validate_hmac_response(response) when byte_size(response) == 32, do: :ok
  defp validate_hmac_response(_response), do: {:error, :invalid_response}

  defp fetch_device_id(attrs) do
    value = dual_key_get(attrs, :share_participant_device_id)

    case Ecto.UUID.cast(value) do
      {:ok, device_id} -> {:ok, device_id}
      :error -> {:error, {:invalid_field, :share_participant_device_id}}
    end
  end

  defp fetch_uuid(attrs, field) do
    value = dual_key_get(attrs, field)

    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_field, field}}
    end
  end

  defp fetch_share_participant_device_authorization(attrs) do
    case dual_key_get(attrs, :share_participant_device_authorization) do
      artifact when is_map(artifact) -> {:ok, artifact}
      _ -> {:error, {:missing_field, :share_participant_device_authorization}}
    end
  end

  defp fetch_share_capability_authorization(attrs) do
    case dual_key_get(attrs, :share_capability_authorization) do
      artifact when is_map(artifact) -> {:ok, artifact}
      _ -> {:error, {:missing_field, :share_capability_authorization}}
    end
  end

  defp fetch_hybrid_signing_public_key_material(attrs, device_id) do
    material = dual_key_get(attrs, :hybrid_signing_public_key_material)

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
    material = dual_key_get(attrs, :hybrid_encryption_public_key_material)

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

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
