defmodule RefMD.Crypto.Hash do
  @moduledoc false

  alias RefMD.Crypto.Blake3
  alias RefMD.Crypto.Encoding

  @blake3_b64url_re ~r/^[A-Za-z0-9_-]{43}$/
  @hex_re ~r/^[0-9a-fA-F]{64}$/

  def blake3_base64url(bytes) when is_binary(bytes), do: Blake3.hash_base64url(bytes)

  def assert_blake3_base64url!(value), do: assert_blake3_base64url!(value, :none)

  def assert_blake3_base64url!(value, sentinel_policy) when is_binary(value) do
    if sentinel_policy != :none && MapSet.member?(sentinel_policy, value) do
      :ok
    else
      cond do
        Regex.match?(@hex_re, value) ->
          raise ArgumentError, "invalid_blake3_hex"

        not Regex.match?(@blake3_b64url_re, value) ->
          raise ArgumentError, "invalid_blake3_base64url"

        true ->
          Encoding.decode_base64url!(value, 32)
          :ok
      end
    end
  end
end
