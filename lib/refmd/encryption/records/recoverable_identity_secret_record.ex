defmodule RefMD.Encryption.RecoverableIdentitySecretRecord do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS}

  @wrap_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @signature_suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @keys ~w(
    encrypted_identity_hybrid_encryption_private_key_material
    encrypted_identity_hybrid_signing_private_key_material encryption_key_id
    encryption_material_aad_hash id identity_hybrid_encryption_private_key_material_nonce
    identity_hybrid_signing_private_key_material_nonce identity_key_epoch is_current
    previous_record_hash record_hash signing_key_id signing_material_aad_hash user_id
  )

  def validate!(record, expected) when is_map(record) and is_map(expected) do
    exact_keys!(record)
    user_id = Map.fetch!(expected, :user_id)
    epoch = Map.get(expected, :identity_key_epoch, 1)
    previous_record_hash = Map.get(expected, :previous_record_hash, "GENESIS")

    literal!(record["user_id"], user_id)
    literal!(record["identity_key_epoch"], epoch)
    literal!(record["previous_record_hash"], previous_record_hash)
    literal!(record["is_current"], Map.get(expected, :is_current, true))
    uuid_v4!(record["id"])
    literal!(record["signing_key_id"], Map.fetch!(expected, :signing_key_id))
    literal!(record["encryption_key_id"], Map.fetch!(expected, :encryption_key_id))

    signing_ciphertext =
      decode_non_empty!(record["encrypted_identity_hybrid_signing_private_key_material"])

    signing_nonce = decode!(record["identity_hybrid_signing_private_key_material_nonce"], 24)

    encryption_ciphertext =
      decode_non_empty!(record["encrypted_identity_hybrid_encryption_private_key_material"])

    encryption_nonce =
      decode!(record["identity_hybrid_encryption_private_key_material_nonce"], 24)

    signing_aad = %{
      "protocol" => "refmd.hybrid-signing-private-key-material-encryption",
      "version" => 1,
      "purpose" => "identity_hybrid_signing_private_key_material",
      "owner_kind" => "identity",
      "owner_id" => user_id,
      "signing_key_id" => record["signing_key_id"],
      "suite_id" => @signature_suite_id,
      "suite_rank" => 1000,
      "storage_scope" => identity_storage_scope(user_id, epoch)
    }

    encryption_aad = %{
      "protocol" => "refmd.hybrid-encryption-private-key-material-encryption",
      "version" => 1,
      "purpose" => "identity_hybrid_encryption_private_key_material",
      "owner_kind" => "identity",
      "owner_id" => user_id,
      "encryption_key_id" => record["encryption_key_id"],
      "suite_id" => @wrap_suite_id,
      "suite_rank" => 1000,
      "storage_scope" => identity_storage_scope(user_id, epoch)
    }

    literal!(record["signing_material_aad_hash"], hash(signing_aad))
    literal!(record["encryption_material_aad_hash"], hash(encryption_aad))

    preimage = %{
      "protocol" => "refmd.recoverable-identity-secret-record",
      "version" => 1,
      "record_id" => record["id"],
      "user_id" => user_id,
      "identity_key_epoch" => epoch,
      "previous_record_hash" => previous_record_hash,
      "signing_key_id" => record["signing_key_id"],
      "encryption_key_id" => record["encryption_key_id"],
      "signing_ciphertext_hash" => Hash.blake3_base64url(signing_ciphertext),
      "signing_nonce_hash" => Hash.blake3_base64url(signing_nonce),
      "signing_material_aad_hash" => record["signing_material_aad_hash"],
      "encryption_ciphertext_hash" => Hash.blake3_base64url(encryption_ciphertext),
      "encryption_nonce_hash" => Hash.blake3_base64url(encryption_nonce),
      "encryption_material_aad_hash" => record["encryption_material_aad_hash"]
    }

    literal!(record["record_hash"], hash(preimage))
    Map.put(record, "record_preimage", preimage)
  end

  def validate!(_, _), do: raise(ArgumentError, "recoverable_identity_secret_record_invalid")

  def to_attrs!(record, expected) do
    validated = validate!(record, expected)

    %{
      id: validated["id"],
      user_id: validated["user_id"],
      identity_key_epoch: validated["identity_key_epoch"],
      previous_record_hash: validated["previous_record_hash"],
      encrypted_identity_hybrid_encryption_private_key_material:
        decode_non_empty!(validated["encrypted_identity_hybrid_encryption_private_key_material"]),
      identity_hybrid_encryption_private_key_material_nonce:
        decode!(validated["identity_hybrid_encryption_private_key_material_nonce"], 24),
      encryption_key_id: validated["encryption_key_id"],
      encrypted_identity_hybrid_signing_private_key_material:
        decode_non_empty!(validated["encrypted_identity_hybrid_signing_private_key_material"]),
      identity_hybrid_signing_private_key_material_nonce:
        decode!(validated["identity_hybrid_signing_private_key_material_nonce"], 24),
      signing_key_id: validated["signing_key_id"],
      signing_material_aad_hash: validated["signing_material_aad_hash"],
      encryption_material_aad_hash: validated["encryption_material_aad_hash"],
      record_hash: validated["record_hash"],
      is_current: validated["is_current"]
    }
  end

  defp exact_keys!(record) do
    if Enum.sort(Map.keys(record)) != Enum.sort(@keys),
      do: raise(ArgumentError, "recoverable_identity_secret_record_keys_invalid")
  end

  defp identity_storage_scope(user_id, epoch) do
    %{"kind" => "user_identity_key", "user_id" => user_id, "identity_key_epoch" => epoch}
  end

  defp decode!(value, size), do: Encoding.decode_base64url!(value, size)

  defp decode_non_empty!(value) do
    decoded = Encoding.decode_base64url!(value)
    if decoded == <<>>, do: raise(ArgumentError, "recoverable_identity_secret_record_empty")
    decoded
  end

  defp uuid_v4!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, ^value} -> value
      _ -> raise ArgumentError, "recoverable_identity_secret_record_uuid_invalid"
    end
  end

  defp literal!(actual, expected) when actual == expected, do: actual

  defp literal!(_, _),
    do: raise(ArgumentError, "recoverable_identity_secret_record_value_invalid")

  defp hash(value), do: Hash.blake3_base64url(JCS.canonical_bytes!(value))
end
