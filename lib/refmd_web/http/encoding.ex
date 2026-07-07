defmodule RefMDWeb.Http.Encoding do
  @moduledoc false

  alias RefMD.Crypto.Encoding

  @doc "Base64url-encode a binary value, passing through nil."
  def encode_binary(nil), do: nil
  def encode_binary(bin) when is_binary(bin), do: Base.url_encode64(bin, padding: false)

  @doc "Safely decode a base64url string, returning {:ok, bytes} or {:error, :invalid_base64}."
  def decode_binary(base64) when is_binary(base64) do
    {:ok, Encoding.decode_base64url!(base64)}
  rescue
    ArgumentError -> {:error, :invalid_base64}
  end

  def decode_binary(_), do: {:error, :invalid_base64}

  @doc "Decode a required base64url field. Raises on nil or invalid input."
  def decode_binary!(base64) when is_binary(base64) do
    Encoding.decode_base64url!(base64)
  end

  def decode_binary!(_), do: raise(ArgumentError, "missing required binary field")

  @doc "Decode an optional base64url field. Passes through nil, raises on invalid."
  def decode_optional_binary(nil), do: nil

  def decode_optional_binary(val) when is_binary(val) do
    Encoding.decode_base64url!(val)
  end
end
