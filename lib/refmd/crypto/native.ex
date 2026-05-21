defmodule RefMD.Crypto.Native do
  @moduledoc false

  use Rustler, otp_app: :refmd, crate: "refmd_crypto"

  @spec hash(binary()) :: binary()
  def hash(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec mldsa65_verify(binary(), binary(), binary(), binary()) :: boolean()
  def mldsa65_verify(_message, _context, _signature, _public_key),
    do: :erlang.nif_error(:nif_not_loaded)
end
