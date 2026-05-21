defmodule RefMD.Crypto.Blake3 do
  @moduledoc """
  BLAKE3 hash function via Rust NIF.

  Uses dirty CPU scheduler to avoid blocking the Erlang scheduler.
  """

  alias RefMD.Crypto.Native

  @spec hash(binary()) :: binary()
  def hash(data), do: Native.hash(data)

  @spec hash_hex(binary()) :: String.t()
  def hash_hex(data) do
    data |> hash() |> Base.encode16(case: :lower)
  end

  @spec hash_base64url(binary()) :: String.t()
  def hash_base64url(data) do
    data |> hash() |> Base.url_encode64(padding: false)
  end
end
