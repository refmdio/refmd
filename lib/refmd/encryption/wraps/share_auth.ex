defmodule RefMD.Encryption.Wraps.ShareAuth do
  @moduledoc false

  alias RefMD.Crypto.JCS

  @aad_protocol %{"protocol" => "refmd", "version" => 1}
  @share_auth_purpose "server_auth_key_wrap"

  @spec encrypt(binary(), Ecto.UUID.t()) ::
          {:ok, %{ciphertext: binary(), nonce: binary(), key_id: String.t()}} | {:error, term()}
  def encrypt(auth_key, share_id) when is_binary(auth_key) and byte_size(auth_key) == 32 do
    encrypt_with_current_key(auth_key, build_aad(@share_auth_purpose, share_id))
  end

  def encrypt(_auth_key, _share_id), do: {:error, :invalid_auth_key}

  @spec decrypt(binary(), binary(), String.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt(ciphertext_and_tag, nonce, key_id, share_id)
      when is_binary(ciphertext_and_tag) and is_binary(nonce) and is_binary(key_id) do
    decrypt_with_key(ciphertext_and_tag, nonce, key_id, build_aad(@share_auth_purpose, share_id))
  end

  def decrypt(_ciphertext_and_tag, _nonce, _key_id, _share_id),
    do: {:error, :invalid_auth_key_wrap}

  defp build_aad(purpose, share_id) do
    @aad_protocol
    |> Map.merge(%{"purpose" => purpose, "share_id" => share_id})
    |> JCS.canonical_bytes!()
  end

  defp encrypt_with_current_key(plaintext, aad) do
    with {:ok, key_id, key} <- current_key() do
      nonce = :crypto.strong_rand_bytes(12)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, aad, 16, true)

      {:ok, %{ciphertext: ciphertext <> tag, nonce: nonce, key_id: key_id}}
    end
  end

  defp decrypt_with_key(ciphertext_and_tag, nonce, key_id, aad)
       when byte_size(ciphertext_and_tag) >= 16 and byte_size(nonce) == 12 do
    with {:ok, key} <- fetch_key(key_id) do
      ciphertext_size = byte_size(ciphertext_and_tag) - 16
      <<ciphertext::binary-size(^ciphertext_size), tag::binary-size(16)>> = ciphertext_and_tag

      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, ciphertext, aad, tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        :error -> {:error, :decrypt_failed}
      end
    end
  end

  defp decrypt_with_key(_ciphertext_and_tag, _nonce, _key_id, _aad),
    do: {:error, :invalid_auth_key_wrap}

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
