defmodule RefMD.Encryption.KeyDirectory.Body do
  @moduledoc false

  alias RefMD.Encryption.KeyDirectory.DocumentAdmission, as: DocumentAdmission
  alias RefMD.Encryption.KeyDirectory.Invitation, as: Invitation
  alias RefMD.Encryption.KeyDirectory.KeyLifecycle, as: KeyLifecycle
  alias RefMD.Encryption.KeyDirectory.Rotation, as: Rotation
  alias RefMD.Encryption.KeyDirectory.Share, as: Share

  @key_lifecycle_types [
    "device_key_added",
    "identity_key_added",
    "signing_key_revoked",
    "encryption_key_revoked",
    "suite_policy_changed",
    "member_added",
    "member_role_changed",
    "member_removed",
    "wrap_issued"
  ]

  @invitation_types [
    "workspace_invitation_created",
    "workspace_invitation_revoked",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_revoked",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked"
  ]

  @share_types [
    "share_created",
    "share_revoked",
    "share_metadata_updated",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_exclusion_changed",
    "recipient_bound_delivery_admitted"
  ]

  @rotation_types ["rotation_started", "rotation_completed", "old_key_deleted"]
  @document_admission_types [
    "document_update_accepted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "document_snapshot_accepted"
  ]

  @spec assert!(binary(), map()) :: :ok
  def assert!(type, body) when type in @key_lifecycle_types,
    do: KeyLifecycle.assert!(type, body)

  def assert!(type, body) when type in @invitation_types,
    do: Invitation.assert!(type, body)

  def assert!(type, body) when type in @share_types,
    do: Share.assert!(type, body)

  def assert!(type, body) when type in @rotation_types,
    do: Rotation.assert!(type, body)

  def assert!(type, body) when type in @document_admission_types,
    do: DocumentAdmission.assert!(type, body)

  def assert!(_, _), do: raise(ArgumentError, "event_body_invalid")
end
