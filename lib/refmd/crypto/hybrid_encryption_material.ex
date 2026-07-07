defmodule RefMD.Crypto.HybridEncryptionMaterial do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS, Suite}

  @protocol "refmd.hybrid-encryption-key-material"
  @x25519_public_bytes 32
  @mlkem768_public_bytes 1184
  @hybrid_public_bytes 1216
  @public_material_keys Enum.sort([
                          "hybrid_public",
                          "mlkem768_public",
                          "owner_id",
                          "owner_kind",
                          "protocol",
                          "suite_id",
                          "suite_rank",
                          "version",
                          "x25519_public"
                        ])

  def assert_public_key_material!(material) when is_map(material) do
    assert_exact_keys!(material, @public_material_keys)
    assert_literal!(material["protocol"], @protocol, "hybrid_encryption_protocol_invalid")
    Suite.assert_protocol_version!(material["version"])
    assert_owner_kind!(material["owner_kind"])
    assert_non_empty_string!(material["owner_id"], "owner_id_invalid")
    Suite.assert_suite_rank_allowed!(material["suite_id"], material["suite_rank"])

    x25519_public =
      Encoding.decode_base64url!(material["x25519_public"], @x25519_public_bytes)

    mlkem768_public =
      Encoding.decode_base64url!(material["mlkem768_public"], @mlkem768_public_bytes)

    hybrid_public =
      Encoding.decode_base64url!(material["hybrid_public"], @hybrid_public_bytes)

    unless hybrid_public == mlkem768_public <> x25519_public do
      raise ArgumentError, "hybrid_encryption_hybrid_public_mismatch"
    end

    :ok
  end

  def assert_public_key_material!(_),
    do: raise(ArgumentError, "hybrid_encryption_material_invalid")

  def compute_key_id!(material) when is_map(material) do
    assert_public_key_material!(material)
    Hash.blake3_base64url(JCS.canonical_bytes!(material))
  end

  def x25519_public!(material) when is_map(material) do
    assert_public_key_material!(material)
    Encoding.decode_base64url!(material["x25519_public"], @x25519_public_bytes)
  end

  def mlkem768_public!(material) when is_map(material) do
    assert_public_key_material!(material)
    Encoding.decode_base64url!(material["mlkem768_public"], @mlkem768_public_bytes)
  end

  defp assert_owner_kind!(kind) when kind in ["identity", "device", "share_participant_device"],
    do: :ok

  defp assert_owner_kind!(_), do: raise(ArgumentError, "owner_kind_invalid")

  defp assert_non_empty_string!(value, _error) when is_binary(value) and byte_size(value) > 0,
    do: :ok

  defp assert_non_empty_string!(_, error), do: raise(ArgumentError, error)

  defp assert_literal!(value, value, _error), do: :ok
  defp assert_literal!(_, _, error), do: raise(ArgumentError, error)

  defp assert_exact_keys!(map, expected_keys) when is_map(map) do
    if Enum.sort(Map.keys(map)) == expected_keys do
      :ok
    else
      raise ArgumentError, "hybrid_encryption_material_keys_invalid"
    end
  end
end
