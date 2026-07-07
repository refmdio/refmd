defmodule RefMD.Encryption.KeyDirectory.Invitation do
  @moduledoc false

  alias RefMD.Crypto.Hash
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  def assert!("workspace_invitation_created", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "invitation_id",
        "invitee_binding",
        "role_id",
        "base_role",
        "kek_version",
        "expires_event_sequence",
        "redeem_authority",
        "bootstrap_key_commitment",
        "bootstrap_package_hash",
        "bootstrap_suite_id",
        "capability_context_hash"
      ])
    )

    A.assert_positive_integer!(body["kek_version"], "kek_version_invalid")
    A.assert_positive_integer!(body["expires_event_sequence"], "expires_event_sequence_invalid")
    A.assert_invitee_binding!(body["invitee_binding"])
    A.assert_redeem_authority!(body["redeem_authority"])
    Hash.assert_blake3_base64url!(body["bootstrap_key_commitment"])
    Hash.assert_blake3_base64url!(body["bootstrap_package_hash"])

    A.assert_literal!(
      body["bootstrap_suite_id"],
      "refmd-v2-invitation-bootstrap-xchacha20poly1305",
      "bootstrap_suite_id_invalid"
    )

    Hash.assert_blake3_base64url!(body["capability_context_hash"])
  end

  def assert!("workspace_invitation_revoked", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["workspace_id", "invitation_id", "revoked_at_event_sequence", "reason"])
    )

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end

  def assert!("workspace_invitation_bootstrap_updated", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "invitation_id",
        "previous_bootstrap_package_hash",
        "bootstrap_package_hash",
        "bootstrap_package_key_maintenance_wrap_hash",
        "key_version_context",
        "updated_at_event_sequence",
        "update_reason"
      ])
    )

    A.assert_exact_keys!(body["key_version_context"], ["workspace_kek_version"])

    A.assert_positive_integer!(
      body["key_version_context"]["workspace_kek_version"],
      "kek_version_invalid"
    )

    A.assert_invitation_bootstrap_update_common!(body)
  end

  def assert!("workspace_invitation_redeemed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "invitation_id",
        "redeemed_user_id",
        "redeemed_device_id",
        "redeemed_encryption_key_id",
        "member_envelope_key_version",
        "member_envelope_hash",
        "redeemed_at_event_sequence"
      ])
    )

    Hash.assert_blake3_base64url!(body["redeemed_encryption_key_id"])
    Hash.assert_blake3_base64url!(body["member_envelope_hash"])
    A.assert_positive_integer!(body["member_envelope_key_version"], "kek_version_invalid")
    A.assert_positive_integer!(body["redeemed_at_event_sequence"], "redeemed_sequence_invalid")
  end

  def assert!("guest_invitation_created", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "guest_invitation_id",
        "guest_grant_template_hash",
        "scope_kind",
        "scope_id",
        "permission",
        "key_version_context",
        "allowed_share_ids_hash",
        "expires_event_sequence",
        "redeem_authority",
        "bootstrap_key_commitment",
        "bootstrap_package_hash",
        "bootstrap_suite_id",
        "capability_context_hash"
      ])
    )

    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])
    A.assert_permission!(body["permission"])

    A.assert_key_version_context!(
      body["key_version_context"],
      body["scope_kind"],
      body["scope_id"]
    )

    A.assert_positive_integer!(body["expires_event_sequence"], "expires_event_sequence_invalid")
    Hash.assert_blake3_base64url!(body["guest_grant_template_hash"])
    Hash.assert_blake3_base64url!(body["allowed_share_ids_hash"])
    A.assert_redeem_authority!(body["redeem_authority"])
    Hash.assert_blake3_base64url!(body["bootstrap_key_commitment"])
    Hash.assert_blake3_base64url!(body["bootstrap_package_hash"])

    A.assert_literal!(
      body["bootstrap_suite_id"],
      "refmd-v2-invitation-bootstrap-xchacha20poly1305",
      "bootstrap_suite_id_invalid"
    )

    Hash.assert_blake3_base64url!(body["capability_context_hash"])
  end

  def assert!("guest_invitation_revoked", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["workspace_id", "guest_invitation_id", "revoked_at_event_sequence", "reason"])
    )

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end

  def assert!("guest_invitation_bootstrap_updated", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "guest_invitation_id",
        "scope_kind",
        "scope_id",
        "previous_bootstrap_package_hash",
        "bootstrap_package_hash",
        "bootstrap_package_key_maintenance_wrap_hash",
        "key_version_context",
        "updated_at_event_sequence",
        "update_reason"
      ])
    )

    A.assert_key_version_context!(
      body["key_version_context"],
      body["scope_kind"],
      body["scope_id"]
    )

    A.assert_invitation_bootstrap_update_common!(body)
  end

  def assert!("guest_invitation_redeemed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "guest_invitation_id",
        "guest_grant_id",
        "guest_user_id",
        "guest_device_id",
        "guest_encryption_key_id",
        "guest_signing_key_id",
        "scope_kind",
        "scope_id",
        "permission",
        "redeemed_at_event_sequence"
      ])
    )

    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])
    A.assert_permission!(body["permission"])
    A.assert_uuid!(body["guest_grant_id"])
    Hash.assert_blake3_base64url!(body["guest_encryption_key_id"])
    Hash.assert_blake3_base64url!(body["guest_signing_key_id"])
    A.assert_positive_integer!(body["redeemed_at_event_sequence"], "redeemed_sequence_invalid")
  end

  def assert!("guest_grant_revoked", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "guest_grant_id",
        "guest_user_id",
        "scope_kind",
        "scope_id",
        "revoked_at_event_sequence",
        "reason"
      ])
    )

    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end

  def assert!("guest_device_revoked", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "guest_user_id",
        "guest_device_id",
        "guest_signing_key_id",
        "guest_encryption_key_id",
        "revoked_at_event_sequence",
        "reason"
      ])
    )

    Hash.assert_blake3_base64url!(body["guest_signing_key_id"])
    Hash.assert_blake3_base64url!(body["guest_encryption_key_id"])

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end
end
