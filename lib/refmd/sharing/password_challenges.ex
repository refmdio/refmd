defmodule RefMD.Sharing.PasswordChallenges do
  @moduledoc """
  Password challenge support for share admission.
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
    ServerEnvelope,
    Share,
    ShareKey,
    SharePasswordChallenge
  }

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
         {:ok, display_name} <- fetch_display_name(attrs),
         {:ok, signing_key} <- fetch_binary(attrs, :device_signing_pub_key),
         {:ok, encryption_key} <- fetch_binary(attrs, :device_encryption_pub_key),
         :ok <- validate_signing_key(signing_key),
         :ok <- validate_encryption_key(encryption_key) do
      respond_password_challenge_tx(
        share_slug,
        response,
        display_name,
        signing_key,
        encryption_key
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
      {:ok, _share, _share_key, _auth_key} -> :ok
      {:error, reason, _challenge, _response} -> Repo.rollback(reason)
    end
  end

  defp respond_password_challenge_tx(
         share_slug,
         response,
         display_name,
         signing_key,
         encryption_key
       ) do
    Repo.transaction(fn ->
      %{token_hash: token_hash} = resolve_password_challenge_target(share_slug)
      now = DateTime.utc_now()

      challenge =
        from(c in SharePasswordChallenge,
          where: c.token_hash == ^token_hash and c.expires_at > ^now,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      respond_password_challenge_record(
        challenge,
        response,
        display_name,
        signing_key,
        encryption_key
      )
    end)
    |> normalize_transaction_result()
  end

  defp respond_password_challenge_record(
         nil,
         _response,
         _display_name,
         _signing_key,
         _encryption_key
       ),
       do: Repo.rollback(:not_found)

  defp respond_password_challenge_record(
         %SharePasswordChallenge{share_id: nil} = challenge_record,
         response,
         _display_name,
         _signing_key,
         _encryption_key
       ) do
    Repo.delete!(challenge_record)
    verify_dummy_password_response!(challenge_record.challenge, response)
  end

  defp respond_password_challenge_record(
         %SharePasswordChallenge{} = challenge_record,
         response,
         display_name,
         signing_key,
         encryption_key
       ) do
    Repo.delete!(challenge_record)

    challenge_record
    |> fetch_password_challenge_share()
    |> verify_password_challenge_share(challenge_record.challenge, response)
    |> create_password_challenge_session(display_name, signing_key, encryption_key)
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
         {%Share{} = protected_share, %ShareKey{} = protected_key},
         challenge,
         response
       ) do
    with true <- Access.share_accepting_participants?(protected_share),
         true <- share_links_enabled?(protected_share),
         true <- protected_share.password_protected,
         {:ok, auth_key} <-
           decrypt_share_auth_key(protected_key, protected_share.id, challenge, response) do
      {:ok, protected_share, protected_key, auth_key}
    else
      _ -> {:error, :not_found, challenge, response}
    end
  end

  defp verify_password_challenge_share(_payload, challenge, response),
    do: {:error, :not_found, challenge, response}

  defp create_password_challenge_session(
         {:ok, protected_share, protected_key, auth_key},
         display_name,
         signing_key,
         encryption_key
       ) do
    session_result =
      Participants.create_participant_session(
        protected_share,
        display_name,
        signing_key,
        encryption_key
      )

    maybe_reencrypt_share_auth_key(protected_key, auth_key, protected_share.id)
    session_result
  end

  defp create_password_challenge_session(
         {:error, :not_found, challenge, response},
         _display_name,
         _signing_key,
         _encryption_key
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
         true <- is_binary(share_key.encrypted_auth_key),
         true <- is_binary(share_key.auth_key_nonce) do
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
        if Access.share_accepting_participants?(share), do: share, else: nil

      _ ->
        nil
    end
  end

  defp decrypt_share_auth_key(share_key, share_id, challenge, response) do
    with encrypted_auth_key when is_binary(encrypted_auth_key) <- share_key.encrypted_auth_key,
         auth_key_nonce when is_binary(auth_key_nonce) <- share_key.auth_key_nonce,
         {:ok, auth_key} <-
           ServerEnvelope.decrypt_share_auth_key(
             encrypted_auth_key,
             auth_key_nonce,
             share_key.server_key_id,
             share_id
           ),
         expected <- :crypto.mac(:hmac, :sha256, auth_key, challenge),
         true <- :crypto.hash_equals(expected, response) do
      {:ok, auth_key}
    else
      _ -> {:error, :not_found}
    end
  end

  defp maybe_reencrypt_share_auth_key(share_key, auth_key, share_id) do
    case ServerEnvelope.encrypt_share_auth_key(auth_key, share_id) do
      {:ok, wrapped_auth_key} ->
        maybe_update_share_wrapped_keys(share_key, wrapped_auth_key, share_id)

      _ ->
        :ok
    end
  end

  defp maybe_update_share_wrapped_keys(share_key, wrapped_auth_key, share_id) do
    if wrapped_auth_key.key_id == share_key.server_key_id do
      :ok
    else
      rewrap_share_key(share_key, wrapped_auth_key, share_id)
    end
  end

  defp rewrap_share_key(share_key, wrapped_auth_key, share_id) do
    with {:ok, encrypted_dek} <- decrypt_existing_share_dek(share_key, share_id),
         {:ok, wrapped_dek} <-
           ServerEnvelope.encrypt_share_dek(encrypted_dek, share_id, share_key.document_id) do
      update_rewrapped_share_key(share_key, wrapped_auth_key, wrapped_dek)
    else
      _ -> :ok
    end
  end

  defp decrypt_existing_share_dek(share_key, share_id) do
    ServerEnvelope.decrypt_share_dek(
      share_key.encrypted_dek,
      share_key.dek_server_nonce,
      share_key.server_key_id,
      share_id,
      share_key.document_id
    )
  end

  defp update_rewrapped_share_key(share_key, wrapped_auth_key, wrapped_dek) do
    from(sk in ShareKey, where: sk.share_id == ^share_key.share_id)
    |> Repo.update_all(
      set: [
        encrypted_dek: wrapped_dek.ciphertext,
        dek_server_nonce: wrapped_dek.nonce,
        encrypted_auth_key: wrapped_auth_key.ciphertext,
        auth_key_nonce: wrapped_auth_key.nonce,
        server_key_id: wrapped_dek.key_id
      ]
    )

    :ok
  end

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
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
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

  defp validate_hmac_response(response) when byte_size(response) == 32, do: :ok
  defp validate_hmac_response(_response), do: {:error, :invalid_response}

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

  defp normalize_transaction_result({:ok, result}), do: {:ok, result}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
