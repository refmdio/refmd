defmodule RefMD.Crypto.Encoding do
  @moduledoc false

  @base64url_re ~r/^[A-Za-z0-9_-]*$/

  @spec encode_base64url(binary()) :: binary()
  def encode_base64url(bytes) when is_binary(bytes), do: Base.url_encode64(bytes, padding: false)

  @spec decode_base64url!(binary()) :: binary()
  def decode_base64url!(value), do: decode_base64url!(value, nil)

  @spec decode_base64url!(binary(), nil | non_neg_integer()) :: binary()
  def decode_base64url!(value, expected_bytes) when is_binary(value) do
    cond do
      not Regex.match?(@base64url_re, value) ->
        raise ArgumentError, "invalid_base64url_alphabet"

      rem(byte_size(value), 4) == 1 ->
        raise ArgumentError, "invalid_base64url_length"

      true ->
        bytes = Base.url_decode64!(value, padding: false)

        if encode_base64url(bytes) != value do
          raise ArgumentError, "non_canonical_base64url"
        end

        if expected_bytes && byte_size(bytes) != expected_bytes do
          raise ArgumentError, "invalid_base64url_decoded_length"
        end

        bytes
    end
  end
end
