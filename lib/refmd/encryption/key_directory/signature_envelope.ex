defmodule RefMD.Encryption.KeyDirectory.SignatureEnvelope do
  @moduledoc false

  alias RefMD.Encryption.KeyDirectory.Assertions

  def parts!(%{"signer" => signer, "signature" => signature})
      when is_map(signer) and is_map(signature) do
    Assertions.assert_non_empty_string!(signer["signer_kind"], "signer_kind_invalid")
    Assertions.assert_non_empty_string!(signer["signing_key_id"], "signing_key_id_invalid")
    {signer, signature}
  end

  def parts!(_), do: raise(ArgumentError, "key_directory_signature_envelope_invalid")
end
