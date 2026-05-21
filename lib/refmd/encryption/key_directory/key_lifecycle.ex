defmodule RefMD.Encryption.KeyDirectory.KeyLifecycle do
  @moduledoc false

  alias RefMD.Crypto.{Hash, Suite}
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  @spec assert!(binary(), map()) :: :ok
  def assert!("device_key_added", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["encryption_key_id", "signing_key_id", "user_id", "device_id"])
    )

    Hash.assert_blake3_base64url!(body["encryption_key_id"])
    Hash.assert_blake3_base64url!(body["signing_key_id"])
  end

  def assert!("identity_key_added", body) do
    A.assert_exact_keys!(body, Enum.sort(["key_id", "key_material_hash"]))
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
    A.assert_exact_keys!(body, Enum.sort(["base_role", "role_id", "user_id", "workspace_id"]))
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
end
