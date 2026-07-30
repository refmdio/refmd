defmodule RefMD.Crypto.Signature.Audit do
  @moduledoc false

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4, transcript_base: 4]

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Crypto.SigningSurface

  @protocol_version 1
  @variants ~w(user_identity user_device workspace_device workspace_guest_device)
  @payload_common_keys ~w(
    authorization_checkpoint_hash
    authorization_checkpoint_scope_id
    authorization_checkpoint_scope_kind
    authorization_checkpoint_sequence
    chain_scope_id
    chain_scope_kind
    covered_event_class
    covered_event_type
    event_hash
    protocol
    sequence
    signer_user_id
    signing_key_id
    version
  )

  def build_audit_checkpoint_transcript!(variant, owner_kind, owner_id, payload)
      when variant in @variants and is_binary(owner_kind) and is_binary(owner_id) and
             is_map(payload) do
    assert_payload!(variant, payload)
    surface = SigningSurface.get_active!("audit_checkpoint", variant)

    transcript =
      transcript_base("audit_checkpoint", surface, owner_kind, owner_id)
      |> Map.merge(%{
        "subject_protocol" => "refmd.signed-audit-checkpoint",
        "subject_version" => @protocol_version,
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(payload)),
        "checkpoint" => checkpoint_projection(payload),
        "signer" => signer_projection(payload),
        "authority_boundary" => %{
          "scope_kind" => payload["authorization_checkpoint_scope_kind"],
          "scope_id" => payload["authorization_checkpoint_scope_id"],
          "checkpoint_protocol" => "refmd.signed-key-directory-checkpoint",
          "checkpoint_version" => @protocol_version,
          "checkpoint_hash_domain" => "BLAKE3-256(JCS(payload))",
          "checkpoint_sequence" => payload["authorization_checkpoint_sequence"],
          "checkpoint_hash" => payload["authorization_checkpoint_hash"],
          "required_authority" => "audit_event_authorized_actor"
        }
      })

    assert_transcript!(transcript, "audit_checkpoint", owner_kind, owner_id)
    transcript
  end

  def build_audit_checkpoint_transcript!(_, _, _, _),
    do: raise(ArgumentError, "audit_checkpoint_transcript_invalid")

  def assert_payload!(variant, payload) when variant in @variants and is_map(payload) do
    device_variant? = variant != "user_identity"
    genesis? = genesis_checkpoint?(payload)

    expected_keys =
      @payload_common_keys ++
        if(device_variant?, do: ["signer_device_id"], else: []) ++
        if(genesis?,
          do: [],
          else: ["previous_signed_checkpoint_hash", "previous_signed_checkpoint_sequence"]
        )

    unless Enum.sort(Map.keys(payload)) == Enum.sort(expected_keys),
      do: raise(ArgumentError, "audit_checkpoint_payload_keys_invalid")

    assert_literal!(payload["protocol"], "refmd.signed-audit-checkpoint")
    assert_literal!(payload["version"], @protocol_version)
    assert_scope_variant!(variant, payload["chain_scope_kind"])
    assert_positive_integer!(payload["sequence"], "audit_checkpoint_sequence_invalid")
    Hash.assert_blake3_base64url!(payload["event_hash"])
    assert_non_empty_string!(payload["chain_scope_id"], "audit_checkpoint_scope_id_invalid")
    assert_non_empty_string!(payload["signer_user_id"], "audit_checkpoint_signer_invalid")
    assert_non_empty_string!(payload["signing_key_id"], "audit_checkpoint_signer_invalid")
    Hash.assert_blake3_base64url!(payload["signing_key_id"])
    assert_literal!(payload["covered_event_class"], "authority")
    assert_non_empty_string!(payload["covered_event_type"], "audit_checkpoint_event_type_invalid")

    if device_variant?,
      do: assert_non_empty_string!(payload["signer_device_id"], "audit_checkpoint_signer_invalid")

    assert_checkpoint_boundaries!(payload)
    :ok
  end

  def assert_payload!(_, _), do: raise(ArgumentError, "audit_checkpoint_payload_invalid")

  def checkpoint_hash!(variant, payload) when variant in @variants and is_map(payload) do
    assert_payload!(variant, payload)
    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  end

  defp checkpoint_projection(payload) do
    %{
      "chain_scope_kind" => payload["chain_scope_kind"],
      "chain_scope_id" => payload["chain_scope_id"],
      "sequence" => payload["sequence"],
      "event_hash" => payload["event_hash"],
      "covered_event_class" => payload["covered_event_class"],
      "covered_event_type" => payload["covered_event_type"]
    }
    |> maybe_put(
      "previous_signed_checkpoint_sequence",
      payload["previous_signed_checkpoint_sequence"]
    )
    |> maybe_put("previous_signed_checkpoint_hash", payload["previous_signed_checkpoint_hash"])
  end

  defp signer_projection(payload) do
    %{
      "user_id" => payload["signer_user_id"],
      "signing_key_id" => payload["signing_key_id"]
    }
    |> maybe_put("device_id", payload["signer_device_id"])
  end

  defp assert_checkpoint_boundaries!(payload) do
    assert_literal!(
      payload["authorization_checkpoint_scope_kind"],
      payload["chain_scope_kind"]
    )

    assert_literal!(payload["authorization_checkpoint_scope_id"], payload["chain_scope_id"])

    if genesis_checkpoint?(payload) do
      assert_genesis_checkpoint!(payload)
    else
      assert_non_genesis_checkpoint!(payload)
    end
  end

  defp assert_genesis_checkpoint!(payload) do
    assert_literal!(payload["authorization_checkpoint_sequence"], 0)
    assert_literal!(payload["authorization_checkpoint_hash"], "GENESIS")
  end

  defp assert_non_genesis_checkpoint!(payload) do
    assert_positive_integer!(
      payload["previous_signed_checkpoint_sequence"],
      "audit_checkpoint_previous_sequence_invalid"
    )

    Hash.assert_blake3_base64url!(payload["previous_signed_checkpoint_hash"])

    assert_positive_integer!(
      payload["authorization_checkpoint_sequence"],
      "audit_checkpoint_authorization_sequence_invalid"
    )

    Hash.assert_blake3_base64url!(payload["authorization_checkpoint_hash"])
  end

  defp genesis_checkpoint?(payload),
    do:
      payload["authorization_checkpoint_sequence"] == 0 and
        payload["authorization_checkpoint_hash"] == "GENESIS"

  defp assert_scope_variant!(variant, "user") when variant in ~w(user_identity user_device),
    do: :ok

  defp assert_scope_variant!(variant, "workspace")
       when variant in ~w(workspace_device workspace_guest_device),
       do: :ok

  defp assert_scope_variant!(_, _), do: raise(ArgumentError, "audit_checkpoint_scope_mismatch")

  defp assert_positive_integer!(value, _error) when is_integer(value) and value > 0, do: :ok
  defp assert_positive_integer!(_, error), do: raise(ArgumentError, error)

  defp assert_non_empty_string!(value, _error) when is_binary(value) and byte_size(value) > 0,
    do: :ok

  defp assert_non_empty_string!(_, error), do: raise(ArgumentError, error)

  defp assert_literal!(value, value), do: :ok
  defp assert_literal!(_, _), do: raise(ArgumentError, "audit_checkpoint_literal_invalid")

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
