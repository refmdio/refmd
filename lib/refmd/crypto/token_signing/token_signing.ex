defmodule RefMD.Crypto.TokenSigning do
  @moduledoc false

  @spec sign(String.t(), term()) :: String.t()
  def sign(salt, data) when is_binary(salt) do
    Phoenix.Token.sign(secret_key_base(), salt, data)
  end

  @spec verify(String.t(), String.t(), keyword()) ::
          {:ok, term()} | {:error, :expired | :invalid | :missing}
  def verify(salt, token, opts \\ []) when is_binary(salt) do
    Phoenix.Token.verify(secret_key_base(), salt, token, opts)
  end

  defp secret_key_base do
    case Application.fetch_env(:refmd, :token_secret_key_base) do
      {:ok, secret} when is_binary(secret) and byte_size(secret) >= 20 ->
        secret

      {:ok, _secret} ->
        raise "token_secret_key_base must be a binary with at least 20 bytes"

      :error ->
        raise "token_secret_key_base is not configured"
    end
  end
end
