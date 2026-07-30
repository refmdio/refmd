defmodule RefMD.Encryption.KeyDirectory.KeyLifecycle do
  @moduledoc false

  alias RefMD.Crypto.{Hash, Suite}
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  def assert!("device_key_added", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["encryption_key_id", "signing_key_id", "user_id", "device_id"])
    )

    Hash.assert_blake3_base64url!(body["encryption_key_id"])
    Hash.assert_blake3_base64url!(body["signing_key_id"])
  end

  def assert!("identity_key_added", body) do
    A.assert_exact_keys!(body, Enum.sort(["key_kind", "key_id", "key_material_hash"]))

    if body["key_kind"] not in ["signing", "encryption"],
      do: raise(ArgumentError, "key_kind_invalid")

    Hash.assert_blake3_base64url!(body["key_id"])
    Hash.assert_blake3_base64url!(body["key_material_hash"])
  end

  def assert!(type, body)
      when type in ["signing_key_revoked", "encryption_key_revoked"] do
    A.assert_exact_keys!(body, Enum.sort(["key_id", "reason", "revoked_at_event_sequence"]))
    Hash.assert_blake3_base64url!(body["key_id"])

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end

  def assert!("suite_policy_changed", body) do
    policy = Suite.current_suite_policy()

    A.assert_exact_keys!(
      body,
      Enum.sort(["allowed_suite_ids", "min_suite_rank", "suite_policy_version"])
    )

    A.assert_literal!(
      body["suite_policy_version"],
      policy["suite_policy_version"],
      "suite_policy_version_invalid"
    )

    A.assert_literal!(body["min_suite_rank"], policy["min_suite_rank"], "min_suite_rank_invalid")

    A.assert_literal!(
      body["allowed_suite_ids"],
      policy["allowed_suite_ids"],
      "allowed_suite_ids_invalid"
    )
  end

  def assert!("member_added", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "base_role",
        "role_id",
        "user_id",
        "workspace_id",
        "workspace_member_envelope_hash"
      ])
    )

    Hash.assert_blake3_base64url!(body["workspace_member_envelope_hash"])
  end

  def assert!("member_role_changed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "changed_at_event_sequence",
        "new_base_role",
        "new_role_id",
        "previous_base_role",
        "previous_role_id",
        "user_id",
        "workspace_id"
      ])
    )

    A.assert_positive_integer!(
      body["changed_at_event_sequence"],
      "member_role_changed_sequence_invalid"
    )
  end

  def assert!("member_removed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["removed_at_event_sequence", "user_id", "workspace_id"])
    )

    A.assert_positive_integer!(
      body["removed_at_event_sequence"],
      "removed_at_event_sequence_invalid"
    )
  end

  def assert!("wrap_issued", body) do
    required = [
      "purpose",
      "recipient",
      "resource",
      "resource_hash",
      "sender",
      "wrap_body_hash",
      "wrap_protocol",
      "wrap_suite_id",
      "wrap_suite_rank",
      "wrap_version"
    ]

    A.assert_exact_keys!(body, Enum.sort(required))
    Hash.assert_blake3_base64url!(body["resource_hash"])
    Hash.assert_blake3_base64url!(body["wrap_body_hash"])
    Suite.assert_suite_rank_allowed!(body["wrap_suite_id"], body["wrap_suite_rank"])
  end

  def assert!("workspace_member_envelope_issued", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "authorization_event_hash",
        "authorization_key_directory_checkpoint_hash",
        "authorization_key_directory_checkpoint_sequence",
        "ciphertext_hash",
        "kek_version",
        "sender_device_id",
        "sender_key_checkpoint_hash",
        "sender_key_checkpoint_sequence",
        "sender_user_id",
        "suite_id",
        "target_identity_encryption_key_id",
        "target_identity_key_material_hash",
        "target_user_id",
        "workspace_id",
        "workspace_member_envelope_hash",
        "wrap_body_hash",
        "wrap_protocol",
        "wrap_purpose",
        "wrap_resource_hash",
        "wrap_version"
      ])
    )

    A.assert_positive_integer!(body["kek_version"], "kek_version_invalid")

    A.assert_literal!(
      body["wrap_protocol"],
      "refmd.signed-pq-hybrid-wrap",
      "wrap_protocol_invalid"
    )

    A.assert_literal!(body["wrap_version"], 1, "wrap_version_invalid")

    A.assert_literal!(
      body["wrap_purpose"],
      "workspace_member_kek_wrap",
      "wrap_purpose_invalid"
    )

    Suite.assert_known_suite_id!(body["suite_id"])

    Enum.each(
      [
        "authorization_event_hash",
        "ciphertext_hash",
        "sender_key_checkpoint_hash",
        "target_identity_encryption_key_id",
        "target_identity_key_material_hash",
        "workspace_member_envelope_hash",
        "wrap_body_hash",
        "wrap_resource_hash"
      ],
      fn field ->
        if body[field] != "GENESIS", do: Hash.assert_blake3_base64url!(body[field])
      end
    )

    A.assert_positive_integer!(
      body["authorization_key_directory_checkpoint_sequence"],
      "authorization_checkpoint_sequence_invalid"
    )

    if body["sender_key_checkpoint_sequence"] != 0 do
      A.assert_positive_integer!(
        body["sender_key_checkpoint_sequence"],
        "sender_checkpoint_sequence_invalid"
      )
    end
  end
end
