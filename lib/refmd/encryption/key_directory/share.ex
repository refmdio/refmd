defmodule RefMD.Encryption.KeyDirectory.Share do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, Signature}
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  def assert!("share_created", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "share_id",
        "scope_kind",
        "scope_id",
        "permission",
        "share_key_version",
        "password_protected",
        "authorization_public_key_material",
        "authorization_public_key_material_hash",
        "share_capability_secret_commitment",
        "password_capability_secret_commitment",
        "password_auth_metadata_hash",
        "max_views",
        "expires_event_sequence",
        "redeem_authority_policy",
        "capability_context_hash"
      ])
    )

    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])
    A.assert_permission!(body["permission"])
    A.assert_positive_integer!(body["share_key_version"], "share_key_version_invalid")
    A.assert_positive_integer!(body["max_views"], "max_views_invalid")
    A.assert_positive_integer!(body["expires_event_sequence"], "expires_event_sequence_invalid")
    Signature.assert_public_key_material!(body["authorization_public_key_material"])

    A.assert_literal!(
      body["authorization_public_key_material"]["owner_kind"],
      "share_capability",
      "authorization_public_key_material_owner_kind_invalid"
    )

    Hash.assert_blake3_base64url!(body["authorization_public_key_material_hash"])
    Hash.assert_blake3_base64url!(body["share_capability_secret_commitment"])

    if body["password_capability_secret_commitment"] != "none" do
      Hash.assert_blake3_base64url!(body["password_capability_secret_commitment"])
    end

    Hash.assert_blake3_base64url!(body["capability_context_hash"])
  end

  def assert!("share_revoked", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort(["workspace_id", "share_id", "revoked_at_event_sequence", "reason"])
    )

    A.assert_positive_integer!(
      body["revoked_at_event_sequence"],
      "revoked_at_event_sequence_invalid"
    )
  end

  def assert!("share_metadata_updated", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "share_id",
        "expires_event_sequence",
        "max_views",
        "updated_at_event_sequence",
        "metadata_update_nonce"
      ])
    )

    A.assert_positive_integer!(body["expires_event_sequence"], "expires_event_sequence_invalid")
    A.assert_positive_integer!(body["max_views"], "max_views_invalid")
    A.assert_positive_integer!(body["updated_at_event_sequence"], "updated_sequence_invalid")
    Encoding.decode_base64url!(body["metadata_update_nonce"], 32)
  end

  def assert!(type, body)
      when type in ["share_key_scope_added", "share_key_scope_replaced"] do
    required =
      if type == "share_key_scope_added" do
        [
          "workspace_id",
          "share_id",
          "parent_share_id",
          "scope_kind",
          "scope_id",
          "document_scope_hash",
          "share_metadata_hash",
          "share_key_version",
          "added_at_event_sequence"
        ]
      else
        [
          "workspace_id",
          "share_id",
          "scope_kind",
          "scope_id",
          "document_scope_hash",
          "share_metadata_hash",
          "share_key_version",
          "previous_share_key_version",
          "replaced_at_event_sequence"
        ]
      end

    A.assert_exact_keys!(body, Enum.sort(required))
    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])
    Hash.assert_blake3_base64url!(body["document_scope_hash"])
    Hash.assert_blake3_base64url!(body["share_metadata_hash"])
    A.assert_positive_integer!(body["share_key_version"], "share_key_version_invalid")
  end

  def assert!("share_key_scope_removed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "share_id",
        "share_key_version",
        "scope_kind",
        "scope_id",
        "document_scope_hash",
        "removed_reason",
        "removed_at_event_sequence",
        "previous_share_scope_event_hash"
      ])
    )

    A.assert_guest_scope!(body["scope_kind"], body["scope_id"])
    Hash.assert_blake3_base64url!(body["document_scope_hash"])
    Hash.assert_blake3_base64url!(body["previous_share_scope_event_hash"])
    A.assert_positive_integer!(body["share_key_version"], "share_key_version_invalid")
    A.assert_positive_integer!(body["removed_at_event_sequence"], "removed_sequence_invalid")
  end

  def assert!("share_exclusion_changed", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "workspace_id",
        "share_id",
        "added_scope_hashes",
        "removed_scope_hashes",
        "changed_at_event_sequence",
        "exclusion_change_nonce"
      ])
    )

    Enum.each(body["added_scope_hashes"], &Hash.assert_blake3_base64url!/1)
    Enum.each(body["removed_scope_hashes"], &Hash.assert_blake3_base64url!/1)
    A.assert_positive_integer!(body["changed_at_event_sequence"], "changed_sequence_invalid")
    Encoding.decode_base64url!(body["exclusion_change_nonce"], 32)
  end

  def assert!("recipient_bound_delivery_admitted", body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "event_type",
        "authorization_id",
        "redeem_attempt_id",
        "authorization_hash",
        "workspace_id",
        "context_kind",
        "context_id",
        "recipient_hash",
        "recipient_device_id",
        "permission",
        "share_session_id",
        "share_session_binding_hash",
        "recipient_nonce_state_hash",
        "live_redeem_challenge_hash",
        "redeem_freshness_proof_hash",
        "previous_workspace_event_sequence",
        "previous_workspace_event_hash",
        "admission_nonce"
      ])
    )

    A.assert_literal!(
      body["event_type"],
      "recipient_bound_delivery_admitted",
      "event_body_type_mismatch"
    )

    A.assert_permission!(body["permission"])

    for key <- [
          "authorization_hash",
          "recipient_hash",
          "share_session_binding_hash",
          "recipient_nonce_state_hash",
          "live_redeem_challenge_hash",
          "redeem_freshness_proof_hash",
          "previous_workspace_event_hash"
        ] do
      Hash.assert_blake3_base64url!(body[key])
    end

    A.assert_positive_integer!(
      body["previous_workspace_event_sequence"],
      "previous_workspace_event_sequence_invalid"
    )

    Encoding.decode_base64url!(body["admission_nonce"], 32)
  end
end
