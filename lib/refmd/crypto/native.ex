defmodule RefMD.Crypto.Native do
  @moduledoc false

  use Rustler, otp_app: :refmd, crate: "refmd_crypto"

  def hash(_data), do: :erlang.nif_error(:nif_not_loaded)

  def mldsa65_verify(_message, _context, _signature, _public_key),
    do: :erlang.nif_error(:nif_not_loaded)
end
