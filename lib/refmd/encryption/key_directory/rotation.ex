defmodule RefMD.Encryption.KeyDirectory.Rotation do
  @moduledoc false

  alias RefMD.Crypto.Hash
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  @spec assert!(binary(), map()) :: :ok
  def assert!("rotation_started", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "event_type",
        "new_key_version",
        "not_before_event_sequence",
        "old_key_version",
        "reason",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ])
    )

    A.assert_literal!(body["event_type"], "rotation_started", "event_body_type_mismatch")
    A.assert_rotation_common!(body)

    A.assert_positive_integer!(
      body["not_before_event_sequence"],
      "not_before_event_sequence_invalid"
    )
  end

  def assert!("rotation_completed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "completed_at_event_sequence",
        "completion_manifest_hash",
        "event_type",
        "new_key_version",
        "old_key_version",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ])
    )

    A.assert_literal!(body["event_type"], "rotation_completed", "event_body_type_mismatch")
    A.assert_rotation_common!(body)

    A.assert_positive_integer!(
      body["completed_at_event_sequence"],
      "completed_at_event_sequence_invalid"
    )

    Hash.assert_blake3_base64url!(body["completion_manifest_hash"])
  end

  def assert!("old_key_deleted", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "deleted_at_event_sequence",
        "deletion_manifest_hash",
        "event_type",
        "old_key_version",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ])
    )

    A.assert_literal!(body["event_type"], "old_key_deleted", "event_body_type_mismatch")
    A.assert_rotation_kind_scope!(body["rotation_kind"], body["scope_kind"])
    A.assert_positive_integer!(body["old_key_version"], "old_key_version_invalid")

    A.assert_positive_integer!(
      body["deleted_at_event_sequence"],
      "deleted_at_event_sequence_invalid"
    )

    Hash.assert_blake3_base64url!(body["deletion_manifest_hash"])
  end
end
