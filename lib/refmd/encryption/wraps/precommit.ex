defmodule RefMD.Encryption.Wraps.Precommit do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS}

  @keys ~w(event_scope hpke protocol protocol_version purpose recipient resource sender suite_id suite_rank)
  @hpke_keys ~w(aead_id ciphertext enc kdf_id kem_id mode)
  @suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"

  def validate!(wrap, expected) when is_map(wrap) and is_map(expected) do
    exact_keys!(wrap, @keys)
    literal!(wrap["protocol"], "refmd.signed-pq-hybrid-wrap")
    literal!(wrap["protocol_version"], 1)
    literal!(wrap["suite_id"], @suite_id)
    literal!(wrap["suite_rank"], 1000)
    literal!(wrap["purpose"], expected.purpose)
    literal!(wrap["resource"], expected.resource)
    literal!(wrap["sender"], expected.sender)
    literal!(wrap["recipient"], expected.recipient)
    literal!(wrap["event_scope"], expected.event_scope)

    hpke = wrap["hpke"]
    exact_keys!(hpke, @hpke_keys)
    literal!(hpke["mode"], "base")
    literal!(hpke["kem_id"], 25_722)
    literal!(hpke["kdf_id"], 1)
    literal!(hpke["aead_id"], 3)
    hpke_enc = decode!(hpke["enc"], 1120)
    ciphertext = decode_non_empty!(hpke["ciphertext"])

    resource_hash = hash(wrap["resource"])
    hpke_info_hash = hash(hpke_info(wrap, resource_hash))
    aad_hash = hash(hpke_aad(wrap))

    wrap_body = %{
      "label" => "RefMD PQ wrap body v1",
      "protocol" => wrap["protocol"],
      "version" => 1,
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource" => wrap["resource"],
      "sender" => wrap["sender"],
      "recipient" => wrap["recipient"],
      "event_scope" => wrap["event_scope"],
      "hpke" => hpke,
      "hpke_info_hash" => hpke_info_hash,
      "aad_hash" => aad_hash
    }

    %{
      wrap: wrap,
      resource_hash: resource_hash,
      wrap_body_hash: hash(wrap_body),
      hpke_info_hash: hpke_info_hash,
      aad_hash: aad_hash,
      hpke_enc_hash: Hash.blake3_base64url(hpke_enc),
      ciphertext_hash: Hash.blake3_base64url(ciphertext)
    }
  end

  def validate!(_, _), do: raise(ArgumentError, "pq_wrap_precommit_invalid")

  def member_envelope_commitment(precommit, expected, derived) do
    commitment = %{
      "protocol" => "refmd.workspace-member-envelope-commitment",
      "version" => 1,
      "workspace_id" => expected.workspace_id,
      "target_user_id" => expected.target_user_id,
      "kek_version" => expected.kek_version,
      "target_identity_encryption_key_id" => expected.target_identity_encryption_key_id,
      "target_identity_key_material_hash" => expected.target_identity_key_material_hash,
      "authorization_key_directory_checkpoint_sequence" => expected.checkpoint_sequence,
      "authorization_key_directory_checkpoint_hash" => expected.checkpoint_hash,
      "wrap_resource_hash" => derived.resource_hash,
      "sender_signing_key_id" => expected.sender["signing_key_id"],
      "recipient_encryption_key_id" => expected.target_identity_encryption_key_id,
      "hpke_enc_hash" => derived.hpke_enc_hash,
      "ciphertext_hash" => derived.ciphertext_hash
    }

    Map.merge(derived, %{
      precommit: precommit,
      commitment: commitment,
      commitment_hash: hash(commitment)
    })
  end

  defp hpke_info(wrap, resource_hash) do
    %{
      "label" => "RefMD HPKE info v1",
      "protocol" => wrap["protocol"],
      "protocol_version" => wrap["protocol_version"],
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource_hash" => resource_hash,
      "sender_user_id" => wrap["sender"]["user_id"],
      "sender_device_id" => wrap["sender"]["device_id"],
      "sender_signing_key_id" => wrap["sender"]["signing_key_id"],
      "sender_key_scope_kind" => wrap["sender"]["key_scope_kind"],
      "sender_key_scope_id" => wrap["sender"]["key_scope_id"],
      "sender_key_checkpoint_hash" => wrap["sender"]["key_checkpoint_hash"],
      "recipient_kind" => wrap["recipient"]["recipient_kind"],
      "recipient_key_id" => wrap["recipient"]["encryption_key_id"],
      "recipient_key_scope_kind" => wrap["recipient"]["key_scope_kind"],
      "recipient_key_scope_id" => wrap["recipient"]["key_scope_id"],
      "recipient_key_checkpoint_hash" => wrap["recipient"]["key_checkpoint_hash"],
      "event_scope_kind" => wrap["event_scope"]["scope_kind"],
      "event_scope_id" => wrap["event_scope"]["scope_id"]
    }
  end

  defp hpke_aad(wrap) do
    %{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => wrap["protocol"],
      "protocol_version" => wrap["protocol_version"],
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource" => wrap["resource"],
      "sender" => wrap["sender"],
      "recipient" => wrap["recipient"],
      "event_scope" => wrap["event_scope"],
      "hpke" => Map.delete(wrap["hpke"], "ciphertext")
    }
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp exact_keys!(value, keys) do
    unless is_map(value) and Enum.sort(Map.keys(value)) == keys,
      do: raise(ArgumentError, "pq_wrap_precommit_keys_invalid")
  end

  defp literal!(value, value), do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "pq_wrap_precommit_binding_invalid")

  defp decode!(value, bytes) do
    Encoding.decode_base64url!(value, bytes)
  end

  defp decode_non_empty!(value) do
    decoded = Encoding.decode_base64url!(value)

    if byte_size(decoded) > 0,
      do: decoded,
      else: raise(ArgumentError, "pq_wrap_precommit_encoding_invalid")
  end
end
