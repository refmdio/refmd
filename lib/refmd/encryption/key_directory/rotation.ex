defmodule RefMD.Encryption.KeyDirectory.Rotation do
  @moduledoc false

  alias RefMD.Crypto.Hash
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  def assert!("rotation_started", %{"rotation_kind" => "identity"} = body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "old_identity_encryption_key_id",
        "new_identity_signing_key_id",
        "new_identity_encryption_key_id",
        "old_user_checkpoint_sequence",
        "old_user_checkpoint_hash",
        "new_key_material_hash",
        "reason",
        "not_before_event_sequence"
      ])
    )

    assert_identity_common!(body)
    A.assert_literal!(body["event_type"], "rotation_started", "event_body_type_mismatch")

    A.assert_positive_integer!(
      body["old_user_checkpoint_sequence"],
      "checkpoint_sequence_invalid"
    )

    A.assert_positive_integer!(
      body["not_before_event_sequence"],
      "not_before_event_sequence_invalid"
    )

    assert_identity_hashes!(body)
    Hash.assert_blake3_base64url!(body["new_key_material_hash"])
  end

  def assert!("rotation_started", %{"rotation_kind" => rotation_kind} = body)
      when rotation_kind != "identity" do
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

  def assert!("rotation_completed", %{"rotation_kind" => rotation_kind} = body)
      when rotation_kind != "identity" do
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

  def assert!("rotation_completed", %{"rotation_kind" => "identity"} = body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "new_identity_signing_key_id",
        "old_user_checkpoint_hash",
        "new_user_checkpoint_hash",
        "completed_at_event_sequence",
        "completion_manifest_hash"
      ])
    )

    assert_identity_common!(body)
    A.assert_literal!(body["event_type"], "rotation_completed", "event_body_type_mismatch")

    A.assert_positive_integer!(
      body["completed_at_event_sequence"],
      "completed_at_event_sequence_invalid"
    )

    assert_identity_hashes!(body)
    Hash.assert_blake3_base64url!(body["completion_manifest_hash"])
  end

  def assert!("old_key_deleted", %{"rotation_kind" => rotation_kind} = body)
      when rotation_kind != "identity" do
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

  def assert!("old_key_deleted", %{"rotation_kind" => "identity"} = body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "old_identity_encryption_key_id",
        "new_identity_signing_key_id",
        "rotation_completed_event_hash",
        "deleted_at_event_sequence",
        "deletion_manifest_hash"
      ])
    )

    assert_identity_common!(body)
    A.assert_literal!(body["event_type"], "old_key_deleted", "event_body_type_mismatch")

    A.assert_positive_integer!(
      body["deleted_at_event_sequence"],
      "deleted_at_event_sequence_invalid"
    )

    assert_identity_hashes!(body)
    Hash.assert_blake3_base64url!(body["rotation_completed_event_hash"])
    Hash.assert_blake3_base64url!(body["deletion_manifest_hash"])
  end

  defp assert_identity_common!(body) do
    A.assert_literal!(body["rotation_kind"], "identity", "rotation_kind_invalid")
    A.assert_literal!(body["scope_kind"], "user", "rotation_scope_invalid")
  end

  defp assert_identity_hashes!(body) do
    body
    |> Map.take([
      "old_identity_signing_key_id",
      "old_identity_encryption_key_id",
      "new_identity_signing_key_id",
      "new_identity_encryption_key_id",
      "old_user_checkpoint_hash",
      "new_user_checkpoint_hash"
    ])
    |> Map.values()
    |> Enum.each(&Hash.assert_blake3_base64url!/1)
  end
end
