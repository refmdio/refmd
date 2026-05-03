defmodule RefMD.Sharing.ServerEnvelope do
  @moduledoc false

  alias RefMD.Crypto

  @aad_protocol %{protocol: "refmd", version: 1}
  @share_slug_recovery_purpose "share_slug_recovery"
  @share_dek_wrap_purpose "share_dek_wrap"
  @share_auth_purpose "share_auth"
  @legacy_share_slug_recovery_purpose "share_slug_server_wrap"
  @legacy_share_dek_wrap_purpose "share_dek_server_wrap"
  @legacy_share_auth_purpose "share_auth_key_server_wrap"

  @spec encrypt_share_slug(binary(), Ecto.UUID.t()) ::
          {:ok, %{ciphertext: binary(), nonce: binary(), key_id: String.t()}} | {:error, term()}
  def encrypt_share_slug(slug_bytes, share_id) when is_binary(slug_bytes) do
    encrypt_with_current_key(slug_bytes, build_aad(@share_slug_recovery_purpose, share_id, nil))
  end

  @spec decrypt_share_slug(binary(), binary(), String.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt_share_slug(ciphertext_and_tag, nonce, key_id, share_id)
      when is_binary(ciphertext_and_tag) and is_binary(nonce) and is_binary(key_id) do
    decrypt_with_key(
      ciphertext_and_tag,
      nonce,
      key_id,
      [
        build_aad(@share_slug_recovery_purpose, share_id, nil),
        build_legacy_aad(@legacy_share_slug_recovery_purpose, share_id, nil)
      ]
    )
  end

  @spec encrypt_share_dek(binary(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{ciphertext: binary(), nonce: binary(), key_id: String.t()}} | {:error, term()}
  def encrypt_share_dek(dek, share_id, document_id) when is_binary(dek) do
    encrypt_with_current_key(dek, build_aad(@share_dek_wrap_purpose, share_id, document_id))
  end

  @spec decrypt_share_dek(binary(), binary(), String.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt_share_dek(ciphertext_and_tag, nonce, key_id, share_id, document_id)
      when is_binary(ciphertext_and_tag) and is_binary(nonce) and is_binary(key_id) do
    decrypt_with_key(
      ciphertext_and_tag,
      nonce,
      key_id,
      [
        build_aad(@share_dek_wrap_purpose, share_id, document_id),
        build_legacy_aad(@legacy_share_dek_wrap_purpose, share_id, document_id)
      ]
    )
  end

  @spec encrypt_share_auth_key(binary(), Ecto.UUID.t()) ::
          {:ok, %{ciphertext: binary(), nonce: binary(), key_id: String.t()}} | {:error, term()}
  def encrypt_share_auth_key(auth_key, share_id) when is_binary(auth_key) do
    encrypt_with_current_key(auth_key, build_aad(@share_auth_purpose, share_id, nil))
  end

  @spec decrypt_share_auth_key(binary(), binary(), String.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt_share_auth_key(ciphertext_and_tag, nonce, key_id, share_id)
      when is_binary(ciphertext_and_tag) and is_binary(nonce) and is_binary(key_id) do
    decrypt_with_key(
      ciphertext_and_tag,
      nonce,
      key_id,
      [
        build_aad(@share_auth_purpose, share_id, nil),
        build_legacy_aad(@legacy_share_auth_purpose, share_id, nil)
      ]
    )
  end

  defp split_tag(ciphertext_and_tag) when byte_size(ciphertext_and_tag) >= 16 do
    ciphertext_size = byte_size(ciphertext_and_tag) - 16
    <<ciphertext::binary-size(ciphertext_size), tag::binary-size(16)>> = ciphertext_and_tag
    {ciphertext, tag}
  end

  defp build_aad(purpose, share_id, document_id) do
    @aad_protocol
    |> Map.merge(%{purpose: purpose, share_id: share_id})
    |> maybe_put_document_id(document_id)
    |> Crypto.jcs_canonicalize()
  end

  defp build_legacy_aad(purpose, share_id, document_id) do
    Jason.encode!(
      @aad_protocol
      |> Map.merge(%{purpose: purpose, share_id: share_id})
      |> maybe_put_document_id(document_id)
    )
  end

  defp maybe_put_document_id(aad, nil), do: aad
  defp maybe_put_document_id(aad, document_id), do: Map.put(aad, :document_id, document_id)

  defp encrypt_with_current_key(plaintext, aad) when is_binary(plaintext) do
    with {:ok, key_id, key} <- current_key() do
      nonce = :crypto.strong_rand_bytes(12)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, aad, 16, true)

      {:ok, %{ciphertext: ciphertext <> tag, nonce: nonce, key_id: key_id}}
    end
  end

  defp decrypt_with_key(ciphertext_and_tag, nonce, key_id, aads) when is_list(aads) do
    with {:ok, key} <- fetch_key(key_id) do
      {ciphertext, tag} = split_tag(ciphertext_and_tag)
      decrypt_with_aads(key, nonce, ciphertext, tag, aads)
    end
  end

  defp decrypt_with_aads(_key, _nonce, _ciphertext, _tag, []), do: {:error, :decrypt_failed}

  defp decrypt_with_aads(key, nonce, ciphertext, tag, [aad | rest]) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, ciphertext, aad, tag, false) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      :error -> decrypt_with_aads(key, nonce, ciphertext, tag, rest)
    end
  end

  defp current_key do
    with key_id when is_binary(key_id) <- Application.get_env(:refmd, :share_server_key_id),
         {:ok, key} <- fetch_key(key_id) do
      {:ok, key_id, key}
    else
      nil -> {:error, :missing_server_key_id}
      error -> error
    end
  end

  defp fetch_key(key_id) do
    keys = Application.get_env(:refmd, :share_server_keys, %{})

    case Map.get(keys, key_id) do
      key when is_binary(key) and byte_size(key) == 32 ->
        {:ok, key}

      key when is_binary(key) ->
        case Base.url_decode64(key, padding: false) do
          {:ok, decoded} when byte_size(decoded) == 32 -> {:ok, decoded}
          _ -> {:error, :invalid_server_key}
        end

      _ ->
        {:error, :missing_server_key}
    end
  end
end
