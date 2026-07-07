defmodule RefMD.TestCrypto.Native do
  @moduledoc false

  use Rustler,
    otp_app: :refmd,
    crate: "refmd_test_crypto",
    path: "native/refmd_test_crypto"

  def keypair_from_seed(_seed), do: :erlang.nif_error(:nif_not_loaded)

  def sign(_message, _context, _private_key), do: :erlang.nif_error(:nif_not_loaded)
end
