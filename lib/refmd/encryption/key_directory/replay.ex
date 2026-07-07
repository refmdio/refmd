defmodule RefMD.Encryption.KeyDirectory.Replay do
  @moduledoc false

  import RefMD.Encryption.KeyDirectory.State

  alias RefMD.Crypto.Suite
  alias RefMD.Encryption.KeyDirectory.{Assertions, Envelope, Payload}
  alias RefMD.Encryption.KeyDirectory.Semantics, as: Semantics

  @checkpoint_noop_event_types [
    "suite_policy_changed",
    "member_added",
    "member_role_changed",
    "member_removed",
    "wrap_issued",
    "rotation_started",
    "rotation_completed",
    "old_key_deleted",
    "share_created",
    "share_exclusion_changed",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_metadata_updated",
    "recipient_bound_delivery_admitted",
    "share_revoked",
    "workspace_invitation_created",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_revoked",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_revoked",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked",
    "document_update_accepted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "document_snapshot_accepted"
  ]

  defdelegate assert_event_semantics_against_checkpoint!(payload, checkpoint_payload),
    to: Semantics

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => "identity_key_added"} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      ) do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    signing_entry = key_entry_by_id!(candidate_payload, payload["body"]["key_id"])
    assert_key_entry_valid_from_event!(signing_entry, payload)

    candidate_payload["identity_keys"]
    |> identity_entries_for_event(payload)
    |> append_identity_entries!(replay_payload)
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => "device_key_added"} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      ) do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    signing_entry = key_entry_by_id!(candidate_payload, payload["body"]["signing_key_id"])
    encryption_entry = key_entry_by_id!(candidate_payload, payload["body"]["encryption_key_id"])

    assert_key_entry_valid_from_event!(signing_entry, payload)
    assert_key_entry_valid_from_event!(encryption_entry, payload)

    replay_payload
    |> update_key_entries!("device_keys", signing_entry)
    |> update_key_entries!("device_keys", encryption_entry)
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => "suite_policy_changed"} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      ) do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)

    replay_payload
    |> Map.put("suite_policy_version", payload["body"]["suite_policy_version"])
    |> Map.put("min_suite_rank", payload["body"]["min_suite_rank"])
    |> Map.put("allowed_suite_ids", payload["body"]["allowed_suite_ids"])
    |> Map.put(
      "allowed_suite_ids_hash",
      Suite.canonical_allowed_suite_ids_hash(%{
        "allowed_suite_ids" => payload["body"]["allowed_suite_ids"]
      })
    )
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => event_type} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      )
      when event_type in ["signing_key_revoked", "encryption_key_revoked"] do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    revoke_key_entry!(replay_payload, payload["body"]["key_id"], payload)
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => event_type} = payload,
        signatures,
        candidate_payload,
        authorized_share_participant_keys
      )
      when event_type in [
             "document_update_accepted",
             "document_write_session_admitted",
             "document_snapshot_accepted"
           ] do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)

    apply_document_admission_event_to_checkpoint_payload!(
      replay_payload,
      payload,
      signatures,
      candidate_payload,
      authorized_share_participant_keys
    )
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => event_type} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      )
      when event_type in ["workspace_invitation_created", "guest_invitation_created"] do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)

    signing_key_id = payload["body"]["redeem_authority"]["signing_key_id"]
    key_material = payload["body"]["redeem_authority"]["hybrid_signing_public_key_material"]

    Assertions.assert_literal!(
      Payload.key_id!(key_material),
      signing_key_id,
      "invitation_redeem_authority_key_mismatch"
    )

    Assertions.assert_literal!(
      key_material["owner_kind"],
      "invitation_redeem_authority",
      "invitation_redeem_authority_owner_kind_invalid"
    )

    expected_invitation_id =
      case event_type do
        "workspace_invitation_created" -> payload["body"]["invitation_id"]
        "guest_invitation_created" -> payload["body"]["guest_invitation_id"]
      end

    Assertions.assert_literal!(
      key_material["owner_id"],
      expected_invitation_id,
      "invitation_redeem_authority_owner_id_mismatch"
    )

    replay_payload
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => "workspace_invitation_redeemed"} = payload,
        signatures,
        candidate_payload,
        _authorized_share_participant_keys
      ) do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    body = payload["body"]
    assert_invitation_redeem_authority_matches!(signatures, body, "invitation_id")
    user_id = body["redeemed_user_id"]
    device_id = body["redeemed_device_id"]

    identity_entry =
      key_entry_by_owner_protocol!(
        candidate_payload,
        "identity",
        user_id,
        "refmd.hybrid-encryption-key-material"
      )

    signing_entry =
      key_entry_by_owner_protocol!(
        candidate_payload,
        "device",
        device_id,
        "refmd.hybrid-signing-key-material"
      )

    encryption_entry =
      key_entry_by_id!(candidate_payload, body["redeemed_encryption_key_id"])

    Assertions.assert_literal!(
      identity_entry["key_material"]["owner_kind"],
      "identity",
      "redeemed_identity_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      identity_entry["key_material"]["owner_id"],
      user_id,
      "redeemed_identity_owner_id_mismatch"
    )

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_kind"],
      "device",
      "redeemed_device_signing_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_id"],
      device_id,
      "redeemed_device_signing_owner_id_mismatch"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_kind"],
      "device",
      "redeemed_device_encryption_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_id"],
      device_id,
      "redeemed_device_encryption_owner_id_mismatch"
    )

    assert_key_entry_valid_from_event!(identity_entry, payload)
    assert_key_entry_valid_from_event!(signing_entry, payload)
    assert_key_entry_valid_from_event!(encryption_entry, payload)

    replay_payload
    |> update_key_entries!("identity_keys", identity_entry)
    |> update_key_entries!("device_keys", signing_entry)
    |> update_key_entries!("device_keys", encryption_entry)
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => "guest_invitation_redeemed"} = payload,
        signatures,
        candidate_payload,
        _authorized_share_participant_keys
      ) do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    body = payload["body"]
    assert_invitation_redeem_authority_matches!(signatures, body, "guest_invitation_id")
    user_id = body["guest_user_id"]
    device_id = body["guest_device_id"]

    identity_entry =
      key_entry_by_owner_protocol(
        replay_payload,
        "identity",
        user_id,
        "refmd.hybrid-encryption-key-material"
      ) ||
        key_entry_by_owner_protocol!(
          candidate_payload,
          "identity",
          user_id,
          "refmd.hybrid-encryption-key-material"
        )

    existing_signing_entry = find_key_entry_by_id(replay_payload, body["guest_signing_key_id"])

    signing_entry =
      existing_signing_entry || key_entry_by_id!(candidate_payload, body["guest_signing_key_id"])

    existing_encryption_entry =
      find_key_entry_by_id(replay_payload, body["guest_encryption_key_id"])

    encryption_entry =
      existing_encryption_entry ||
        key_entry_by_id!(candidate_payload, body["guest_encryption_key_id"])

    Assertions.assert_literal!(
      identity_entry["key_material"]["owner_kind"],
      "identity",
      "guest_identity_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      identity_entry["key_material"]["owner_id"],
      user_id,
      "guest_identity_owner_id_mismatch"
    )

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_kind"],
      "device",
      "guest_device_signing_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      signing_entry["key_material"]["owner_id"],
      device_id,
      "guest_device_signing_owner_id_mismatch"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_kind"],
      "device",
      "guest_device_encryption_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      encryption_entry["key_material"]["owner_id"],
      device_id,
      "guest_device_encryption_owner_id_mismatch"
    )

    if is_nil(
         key_entry_by_owner_protocol(
           replay_payload,
           "identity",
           user_id,
           "refmd.hybrid-encryption-key-material"
         )
       ),
       do: assert_key_entry_valid_from_event!(identity_entry, payload)

    if is_nil(existing_signing_entry),
      do: assert_key_entry_valid_from_event!(signing_entry, payload)

    if is_nil(existing_encryption_entry),
      do: assert_key_entry_valid_from_event!(encryption_entry, payload)

    replay_payload
    |> update_key_entries_if_missing!("identity_keys", identity_entry)
    |> update_key_entries_if_missing!("device_keys", signing_entry)
    |> update_key_entries_if_missing!("device_keys", encryption_entry)
  end

  def apply_event_to_checkpoint_payload!(
        replay_payload,
        %{"event_type" => event_type} = payload,
        _signatures,
        candidate_payload,
        _authorized_share_participant_keys
      )
      when event_type in @checkpoint_noop_event_types do
    assert_event_semantics_against_checkpoint!(payload, candidate_payload)
    replay_payload
  end

  def apply_event_to_checkpoint_payload!(
        _replay_payload,
        payload,
        _signatures,
        _candidate_payload,
        _authorized_share_participant_keys
      ) do
    raise ArgumentError,
          "key_directory_event_semantic_validator_missing:#{payload["event_type"]}"
  end

  def apply_document_admission_event_to_checkpoint_payload!(
        replay_payload,
        payload,
        signatures,
        candidate_payload,
        authorized_share_participant_keys
      ) do
    case share_participant_signer(signatures) do
      nil ->
        replay_payload

      signer ->
        signing_key_id = signer["signing_key_id"]

        if Enum.any?(replay_payload["share_participant_keys"], &(&1["key_id"] == signing_key_id)) do
          replay_payload
        else
          entry =
            authorized_share_participant_key_entry!(
              authorized_share_participant_keys,
              signing_key_id
            )

          Assertions.assert_literal!(
            share_participant_key_entry_by_id!(candidate_payload, signing_key_id),
            entry,
            "share_participant_key_entry_unauthorized"
          )

          assert_key_entry_active_at_sequence!(
            candidate_payload,
            signing_key_id,
            payload["sequence"]
          )

          Assertions.assert_literal!(
            entry["key_material"]["owner_kind"],
            "share_participant_device",
            "share_participant_owner_kind_invalid"
          )

          Assertions.assert_literal!(
            entry["key_material"]["owner_id"],
            signer["share_participant_device_id"],
            "share_participant_owner_id_mismatch"
          )

          update_key_entries!(replay_payload, "share_participant_keys", entry)
        end
    end
  end

  def identity_entries_for_event(entries, payload) do
    Enum.filter(entries, fn entry ->
      entry["valid_from"] == event_ref!(payload) and
        entry["key_material"]["owner_kind"] == "identity"
    end)
  end

  def append_identity_entries!([], _replay_payload),
    do: raise(ArgumentError, "key_directory_key_entry_missing")

  def append_identity_entries!(entries, replay_payload) do
    Enum.reduce(entries, replay_payload, fn entry, acc ->
      update_key_entries!(acc, "identity_keys", entry)
    end)
  end

  defp key_entry_by_owner_protocol!(checkpoint_payload, owner_kind, owner_id, protocol) do
    case key_entry_by_owner_protocol(checkpoint_payload, owner_kind, owner_id, protocol) do
      %{} = entry -> entry
      nil -> raise ArgumentError, "key_directory_owner_key_entry_missing"
    end
  end

  defp key_entry_by_owner_protocol(checkpoint_payload, owner_kind, owner_id, protocol) do
    checkpoint_payload
    |> key_directory_authority_entries()
    |> Enum.find(fn
      %{
        "key_material" => %{
          "owner_kind" => ^owner_kind,
          "owner_id" => ^owner_id,
          "protocol" => ^protocol
        }
      } ->
        true

      _ ->
        false
    end)
  end

  def initial_checkpoint_payload!(checkpoint_payload, event_envelopes) do
    base =
      checkpoint_payload
      |> Map.put("identity_keys", [])
      |> Map.put("device_keys", [])
      |> Map.put("share_participant_keys", [])
      |> Map.put("revoked_key_ids", [])

    Enum.reduce(event_envelopes, base, fn envelope, replay_payload ->
      apply_event_to_checkpoint_payload!(
        replay_payload,
        Envelope.payload!(envelope, :event),
        Envelope.signatures!(envelope),
        checkpoint_payload,
        share_participant_entries_by_id(checkpoint_payload)
      )
    end)
  end
end
