defmodule RefMD.Encryption.KeyDirectory.Semantics do
  @moduledoc false

  import RefMD.Encryption.KeyDirectory.State

  alias RefMD.Crypto.{Hash, JCS, Suite}
  alias RefMD.Encryption.KeyDirectory.Assertions

  def assert_event_semantics_against_checkpoint!(
        %{
          "event_type" => type,
          "scope_kind" => scope_kind,
          "scope_id" => scope_id,
          "sequence" => sequence,
          "body" => body
        },
        _checkpoint_payload
      )
      when type in [
             "rotation_started",
             "rotation_completed",
             "old_key_deleted"
           ] do
    Assertions.assert_literal!(body["event_type"], type, "event_body_type_mismatch")
    assert_rotation_scope!(scope_kind, scope_id, body)
    assert_rotation_sequence!(type, body, sequence)
  end

  def assert_event_semantics_against_checkpoint!(
        %{
          "event_type" => type,
          "scope_kind" => "workspace",
          "scope_id" => scope_id,
          "sequence" => sequence,
          "actor" => actor,
          "previous_event_hash" => previous_event_hash,
          "body" => body
        },
        _checkpoint_payload
      )
      when type in [
             "document_write_session_admitted",
             "document_snapshot_accepted"
           ] do
    Assertions.assert_literal!(body["event_type"], type, "event_body_type_mismatch")

    Assertions.assert_literal!(
      body["workspace_id"],
      scope_id,
      "document_admission_workspace_mismatch"
    )

    Assertions.assert_literal!(
      body["actor_hash"],
      Hash.blake3_base64url(JCS.canonical_bytes!(actor)),
      "document_admission_actor_hash_mismatch"
    )

    Assertions.assert_literal!(
      body["previous_workspace_event_sequence"],
      sequence - 1,
      "document_admission_previous_sequence_mismatch"
    )

    Assertions.assert_literal!(
      body["previous_workspace_event_hash"],
      previous_event_hash,
      "document_admission_previous_hash_mismatch"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{
          "event_type" => "document_write_state_changed",
          "scope_kind" => "workspace",
          "scope_id" => scope_id,
          "sequence" => sequence,
          "actor" => actor,
          "previous_event_hash" => previous_event_hash,
          "body" => body
        },
        checkpoint_payload
      ) do
    Assertions.assert_literal!(
      body["workspace_id"],
      scope_id,
      "document_write_state_workspace_mismatch"
    )

    Assertions.assert_literal!(
      body["previous_workspace_event_sequence"],
      sequence - 1,
      "document_write_state_previous_sequence_mismatch"
    )

    Assertions.assert_literal!(
      body["previous_workspace_event_hash"],
      previous_event_hash,
      "document_write_state_previous_hash_mismatch"
    )

    Assertions.assert_literal!(
      actor["signer_kind"],
      "device",
      "document_write_state_actor_kind_invalid"
    )

    assert_key_entry_active_at_sequence!(
      checkpoint_payload,
      actor["signing_key_id"],
      sequence
    )

    entry = key_entry_by_id!(checkpoint_payload, actor["signing_key_id"])
    material = entry["key_material"]

    Assertions.assert_literal!(
      material["owner_kind"],
      "device",
      "document_write_state_actor_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      material["owner_id"],
      actor["device_id"],
      "document_write_state_actor_owner_id_invalid"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => "identity_key_added", "body" => body},
        checkpoint_payload
      ) do
    entry = key_entry_by_id!(checkpoint_payload, body["key_id"])
    material_hash = Hash.blake3_base64url(JCS.canonical_bytes!(entry["key_material"]))

    Assertions.assert_literal!(
      body["key_material_hash"],
      material_hash,
      "identity_key_material_hash_mismatch"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => "device_key_added", "body" => body},
        checkpoint_payload
      ) do
    signing_entry = key_entry_by_id!(checkpoint_payload, body["signing_key_id"])
    encryption_entry = key_entry_by_id!(checkpoint_payload, body["encryption_key_id"])

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_kind"],
      "device",
      "device_signing_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_id"],
      body["device_id"],
      "device_signing_owner_id_mismatch"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_kind"],
      "device",
      "device_encryption_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_id"],
      body["device_id"],
      "device_encryption_owner_id_mismatch"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => "member_added", "scope_id" => scope_id, "body" => body},
        _checkpoint_payload
      ) do
    Assertions.assert_literal!(body["workspace_id"], scope_id, "member_added_scope_mismatch")
  end

  def assert_event_semantics_against_checkpoint!(
        %{
          "event_type" => "member_role_changed",
          "sequence" => sequence,
          "scope_id" => scope_id,
          "body" => body
        },
        _checkpoint_payload
      ) do
    Assertions.assert_literal!(
      body["workspace_id"],
      scope_id,
      "member_role_changed_scope_mismatch"
    )

    Assertions.assert_literal!(
      body["changed_at_event_sequence"],
      sequence,
      "member_role_changed_sequence_mismatch"
    )

    Assertions.assert_positive_integer!(
      body["permission_version"],
      "member_role_changed_permission_version_invalid"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{
          "event_type" => "member_removed",
          "sequence" => sequence,
          "scope_id" => scope_id,
          "body" => body
        },
        _checkpoint_payload
      ) do
    Assertions.assert_literal!(body["workspace_id"], scope_id, "member_removed_scope_mismatch")

    Assertions.assert_literal!(
      body["removed_at_event_sequence"],
      sequence,
      "member_removed_sequence_mismatch"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => "suite_policy_changed", "body" => body},
        _checkpoint_payload
      ) do
    policy = Suite.current_suite_policy()

    Assertions.assert_literal!(
      body["suite_policy_version"],
      policy["suite_policy_version"],
      "suite_policy_version_invalid"
    )

    Assertions.assert_literal!(
      body["min_suite_rank"],
      policy["min_suite_rank"],
      "min_suite_rank_invalid"
    )

    Assertions.assert_literal!(
      body["allowed_suite_ids"],
      policy["allowed_suite_ids"],
      "allowed_suite_ids_invalid"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => type, "sequence" => sequence, "body" => body},
        checkpoint_payload
      )
      when type in ["signing_key_revoked", "encryption_key_revoked"] do
    key_entry_by_id!(checkpoint_payload, body["key_id"])

    Assertions.assert_literal!(
      body["revoked_at_event_sequence"],
      sequence,
      "key_revoked_sequence_mismatch"
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => "wrap_issued", "scope_kind" => scope_kind, "scope_id" => scope_id} =
          payload,
        checkpoint_payload
      ) do
    {sender, recipient} = assert_wrap_issued_static_semantics!(payload, scope_kind, scope_id)

    assert_key_entry_active_at_sequence!(
      checkpoint_payload,
      sender["signing_key_id"],
      payload["sequence"]
    )

    assert_key_entry_active_at_sequence!(
      checkpoint_payload,
      recipient["encryption_key_id"],
      payload["sequence"]
    )
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => event_type, "scope_kind" => "workspace", "scope_id" => scope_id} =
          payload,
        checkpoint_payload
      )
      when event_type in [
             "share_created",
             "share_revoked",
             "share_metadata_updated",
             "share_key_scope_added",
             "share_key_scope_replaced",
             "share_key_scope_removed",
             "share_exclusion_changed",
             "recipient_bound_delivery_admitted"
           ] do
    actor = payload["actor"]
    body = payload["body"]
    Assertions.assert_literal!(body["workspace_id"], scope_id, "share_event_workspace_mismatch")
    Assertions.assert_literal!(actor["signer_kind"], "device", "share_event_actor_kind_invalid")

    assert_key_entry_active_at_sequence!(
      checkpoint_payload,
      actor["signing_key_id"],
      payload["sequence"]
    )

    entry = key_entry_by_id!(checkpoint_payload, actor["signing_key_id"])
    material = entry["key_material"]

    Assertions.assert_literal!(
      material["owner_kind"],
      "device",
      "share_event_actor_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      material["owner_id"],
      actor["device_id"],
      "share_event_actor_owner_id_invalid"
    )

    assert_share_event_sequence!(event_type, payload)
  end

  def assert_event_semantics_against_checkpoint!(
        %{"event_type" => event_type, "scope_kind" => "workspace", "scope_id" => scope_id} =
          payload,
        _checkpoint_payload
      )
      when event_type in [
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
           ] do
    body = payload["body"]
    Assertions.assert_literal!(body["workspace_id"], scope_id, "invitation_workspace_mismatch")
    assert_invitation_event_sequence!(event_type, payload)
  end

  def assert_event_semantics_against_checkpoint!(payload, _checkpoint_payload) do
    raise ArgumentError,
          "key_directory_event_semantic_validator_missing:#{payload["event_type"]}"
  end

  def assert_invitation_admission_wrap_event_semantics!(
        %{"event_type" => "wrap_issued", "scope_kind" => scope_kind, "scope_id" => scope_id} =
          payload,
        _checkpoint_payload
      ) do
    assert_wrap_issued_static_semantics!(payload, scope_kind, scope_id,
      allow_user_scoped_recipient: true
    )

    :ok
  end

  defp assert_wrap_issued_static_semantics!(payload, scope_kind, scope_id, opts \\ []) do
    body = payload["body"]
    resource_hash = Hash.blake3_base64url(JCS.canonical_bytes!(body["resource"]))

    Assertions.assert_literal!(
      body["resource_hash"],
      resource_hash,
      "wrap_resource_hash_mismatch"
    )

    sender = body["sender"]
    recipient = body["recipient"]
    actor = payload["actor"]

    Assertions.assert_literal!(actor["user_id"], sender["user_id"], "wrap_sender_actor_mismatch")

    Assertions.assert_literal!(
      actor["device_id"],
      sender["device_id"],
      "wrap_sender_actor_mismatch"
    )

    Assertions.assert_literal!(
      actor["signing_key_id"],
      sender["signing_key_id"],
      "wrap_sender_actor_mismatch"
    )

    Assertions.assert_literal!(sender["key_scope_kind"], scope_kind, "wrap_sender_scope_mismatch")
    Assertions.assert_literal!(sender["key_scope_id"], scope_id, "wrap_sender_scope_mismatch")

    assert_wrap_recipient_scope!(recipient, body, scope_kind, scope_id, opts)

    {sender, recipient}
  end

  defp assert_wrap_recipient_scope!(
         %{
           "recipient_kind" => "user_identity",
           "user_id" => user_id,
           "key_scope_kind" => "user",
           "key_scope_id" => user_id
         },
         %{
           "purpose" => "workspace_member_kek_wrap",
           "resource" => %{"target_user_id" => user_id}
         },
         _scope_kind,
         _scope_id,
         opts
       ) do
    if Keyword.get(opts, :allow_user_scoped_recipient, false),
      do: :ok,
      else: raise(ArgumentError, "wrap_recipient_scope_mismatch")
  end

  defp assert_wrap_recipient_scope!(
         %{
           "recipient_kind" => "invitee",
           "invitee_user_id" => user_id,
           "invitee_device_id" => device_id,
           "key_scope_kind" => "user",
           "key_scope_id" => user_id
         },
         %{
           "purpose" => "workspace_invitation_kek_wrap",
           "resource" => %{
             "redeemed_user_id" => user_id,
             "redeemed_device_id" => device_id
           }
         },
         _scope_kind,
         _scope_id,
         opts
       ) do
    if Keyword.get(opts, :allow_user_scoped_recipient, false),
      do: :ok,
      else: raise(ArgumentError, "wrap_recipient_scope_mismatch")
  end

  defp assert_wrap_recipient_scope!(recipient, _body, scope_kind, scope_id, _opts) do
    Assertions.assert_literal!(
      recipient["key_scope_kind"],
      scope_kind,
      "wrap_recipient_scope_mismatch"
    )

    Assertions.assert_literal!(
      recipient["key_scope_id"],
      scope_id,
      "wrap_recipient_scope_mismatch"
    )
  end

  defp assert_share_event_sequence!("share_revoked", %{"sequence" => sequence, "body" => body}),
    do:
      Assertions.assert_literal!(
        body["revoked_at_event_sequence"],
        sequence,
        "share_revoked_sequence_mismatch"
      )

  defp assert_share_event_sequence!("share_metadata_updated", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["updated_at_event_sequence"],
           sequence,
           "share_metadata_updated_sequence_mismatch"
         )

  defp assert_share_event_sequence!("share_key_scope_added", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["added_at_event_sequence"],
           sequence,
           "share_key_scope_added_sequence_mismatch"
         )

  defp assert_share_event_sequence!("share_key_scope_replaced", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["replaced_at_event_sequence"],
           sequence,
           "share_key_scope_replaced_sequence_mismatch"
         )

  defp assert_share_event_sequence!("share_key_scope_removed", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["removed_at_event_sequence"],
           sequence,
           "share_key_scope_removed_sequence_mismatch"
         )

  defp assert_share_event_sequence!("share_exclusion_changed", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["changed_at_event_sequence"],
           sequence,
           "share_exclusion_changed_sequence_mismatch"
         )

  defp assert_share_event_sequence!("recipient_bound_delivery_admitted", %{
         "sequence" => sequence,
         "previous_event_hash" => previous_event_hash,
         "body" => body
       }) do
    Assertions.assert_literal!(
      body["previous_workspace_event_sequence"],
      sequence - 1,
      "recipient_delivery_previous_sequence_mismatch"
    )

    Assertions.assert_literal!(
      body["previous_workspace_event_hash"],
      previous_event_hash,
      "recipient_delivery_previous_hash_mismatch"
    )
  end

  defp assert_share_event_sequence!(_, _), do: :ok

  defp assert_invitation_event_sequence!("workspace_invitation_revoked", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["revoked_at_event_sequence"],
           sequence,
           "workspace_invitation_revoked_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!("workspace_invitation_bootstrap_updated", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["updated_at_event_sequence"],
           sequence,
           "workspace_invitation_bootstrap_updated_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!("workspace_invitation_redeemed", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["redeemed_at_event_sequence"],
           sequence,
           "workspace_invitation_redeemed_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!("guest_invitation_revoked", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["revoked_at_event_sequence"],
           sequence,
           "guest_invitation_revoked_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!("guest_invitation_bootstrap_updated", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["updated_at_event_sequence"],
           sequence,
           "guest_invitation_bootstrap_updated_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!("guest_invitation_redeemed", %{
         "sequence" => sequence,
         "body" => body
       }),
       do:
         Assertions.assert_literal!(
           body["redeemed_at_event_sequence"],
           sequence,
           "guest_invitation_redeemed_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!(event_type, %{"sequence" => sequence, "body" => body})
       when event_type in ["guest_grant_revoked", "guest_device_revoked"],
       do:
         Assertions.assert_literal!(
           body["revoked_at_event_sequence"],
           sequence,
           "#{event_type}_sequence_mismatch"
         )

  defp assert_invitation_event_sequence!(_, _), do: :ok

  defp assert_rotation_scope!("workspace", _workspace_id, %{
         "rotation_kind" => "dek",
         "scope_kind" => "document",
         "scope_id" => document_id
       })
       when is_binary(document_id),
       do: :ok

  defp assert_rotation_scope!(scope_kind, scope_id, body) do
    Assertions.assert_literal!(body["scope_kind"], scope_kind, "event_body_scope_mismatch")
    Assertions.assert_literal!(body["scope_id"], scope_id, "event_body_scope_mismatch")
  end

  defp assert_rotation_sequence!("rotation_started", body, sequence) do
    Assertions.assert_literal!(
      body["not_before_event_sequence"],
      sequence,
      "rotation_started_sequence_mismatch"
    )

    unless body["rotation_kind"] == "identity", do: assert_rotation_version_progression!(body)

    if body["rotation_kind"] == "dek" and
         body["reason"] not in ["time_based", "manual", "security", "membership_change"],
       do: raise(ArgumentError, "rotation_reason_invalid")
  end

  defp assert_rotation_sequence!("rotation_completed", body, sequence) do
    Assertions.assert_literal!(
      body["completed_at_event_sequence"],
      sequence,
      "rotation_completed_sequence_mismatch"
    )

    unless body["rotation_kind"] == "identity", do: assert_rotation_version_progression!(body)
  end

  defp assert_rotation_sequence!("old_key_deleted", body, sequence) do
    Assertions.assert_literal!(
      body["deleted_at_event_sequence"],
      sequence,
      "old_key_deleted_sequence_mismatch"
    )
  end

  defp assert_rotation_version_progression!(body) do
    if body["new_key_version"] <= body["old_key_version"] do
      raise ArgumentError, "rotation_key_version_not_increasing"
    end
  end
end
