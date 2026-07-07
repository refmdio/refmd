defmodule RefMD.Encryption.KeyDirectory.Payload do
  @moduledoc false

  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, Signature, Suite}
  alias RefMD.Encryption.KeyDirectory.Body

  @max_safe_integer 9_007_199_254_740_991

  @protocol_version 1
  @event_protocol "refmd.key-directory-event"
  @checkpoint_protocol "refmd.key-directory-checkpoint"
  @valid_scope_kinds ["user", "workspace"]

  @event_types [
    "device_key_added",
    "encryption_key_revoked",
    "identity_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "document_snapshot_accepted",
    "document_update_accepted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "old_key_deleted",
    "rotation_completed",
    "rotation_started",
    "share_created",
    "share_exclusion_changed",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_metadata_updated",
    "recipient_bound_delivery_admitted",
    "share_revoked",
    "signing_key_revoked",
    "suite_policy_changed",
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
    "wrap_issued"
  ]

  @event_payload_keys Enum.sort([
                        "actor",
                        "body",
                        "event_type",
                        "protocol",
                        "scope_id",
                        "scope_kind",
                        "sequence",
                        "version"
                      ])
  @event_payload_keys_with_previous Enum.sort(["previous_event_hash" | @event_payload_keys])

  @checkpoint_payload_keys Enum.sort([
                             "allowed_suite_ids",
                             "covered_event_head",
                             "device_keys",
                             "identity_keys",
                             "issued_at",
                             "min_suite_rank",
                             "protocol",
                             "required_components",
                             "revoked_key_ids",
                             "scope_id",
                             "scope_kind",
                             "sequence",
                             "share_participant_keys",
                             "suite_policy_version",
                             "version"
                           ])
  @checkpoint_payload_keys_with_previous Enum.sort([
                                           "previous_checkpoint_hash"
                                           | @checkpoint_payload_keys
                                         ])

  def event_types, do: @event_types

  def key_id!(%{"protocol" => "refmd.hybrid-signing-key-material"} = material),
    do: Signature.compute_signing_key_id!(material)

  def key_id!(%{"protocol" => "refmd.hybrid-encryption-key-material"} = material),
    do: HybridEncryptionMaterial.compute_key_id!(material)

  def key_id!(_), do: raise(ArgumentError, "key_material_protocol_invalid")

  def key_entry!(key_material, valid_from, revoked_at \\ nil) do
    key_id = key_id!(key_material)

    entry = %{
      "key_id" => key_id,
      "key_material" => key_material,
      "valid_from" => normalize_event_ref!(valid_from)
    }

    entry =
      if is_nil(revoked_at),
        do: entry,
        else: Map.put(entry, "revoked_at", normalize_event_ref!(revoked_at))

    assert_key_entry!(entry)
    entry
  end

  def assert_event_payload!(payload) when is_map(payload) do
    expected_keys =
      if payload["sequence"] == 1,
        do: @event_payload_keys,
        else: @event_payload_keys_with_previous

    assert_exact_keys!(payload, expected_keys)
    assert_literal!(payload["protocol"], @event_protocol, "event_protocol_invalid")
    assert_literal!(payload["version"], @protocol_version, "event_version_invalid")
    assert_scope!(payload["scope_kind"], payload["scope_id"])
    assert_positive_integer!(payload["sequence"], "event_sequence_invalid")

    if payload["event_type"] not in @event_types do
      raise ArgumentError, "event_type_invalid"
    end

    if payload["sequence"] > 1 do
      Hash.assert_blake3_base64url!(payload["previous_event_hash"])
    end

    assert_event_body!(payload["event_type"], payload["body"])
    :ok
  end

  def assert_event_payload!(_), do: raise(ArgumentError, "event_payload_invalid")

  def assert_checkpoint_payload!(payload) when is_map(payload) do
    expected_keys =
      if payload["sequence"] == 1,
        do: @checkpoint_payload_keys,
        else: @checkpoint_payload_keys_with_previous

    assert_exact_keys!(payload, expected_keys)
    assert_literal!(payload["protocol"], @checkpoint_protocol, "checkpoint_protocol_invalid")
    assert_literal!(payload["version"], @protocol_version, "checkpoint_version_invalid")
    assert_scope!(payload["scope_kind"], payload["scope_id"])
    assert_positive_integer!(payload["sequence"], "checkpoint_sequence_invalid")
    assert_iso8601!(payload["issued_at"])

    assert_current_suite_policy!(payload)
    normalize_event_head!(payload["covered_event_head"])
    assert_key_entries!(payload["identity_keys"])
    assert_key_entries!(payload["device_keys"])
    assert_key_entries!(payload["share_participant_keys"])
    assert_revoked_key_ids!(payload["revoked_key_ids"])

    if payload["sequence"] > 1 do
      Hash.assert_blake3_base64url!(payload["previous_checkpoint_hash"])
    end

    :ok
  end

  def assert_checkpoint_payload!(_), do: raise(ArgumentError, "checkpoint_payload_invalid")

  defp assert_current_suite_policy!(payload) do
    policy = Suite.current_suite_policy()

    assert_literal!(
      payload["suite_policy_version"],
      policy["suite_policy_version"],
      "suite_policy_version_invalid"
    )

    assert_literal!(payload["min_suite_rank"], policy["min_suite_rank"], "min_suite_rank_invalid")

    assert_literal!(
      payload["allowed_suite_ids"],
      policy["allowed_suite_ids"],
      "allowed_suite_ids_invalid"
    )

    assert_literal!(
      payload["required_components"],
      policy["required_components"],
      "required_components_invalid"
    )

    :ok
  end

  defp assert_key_entries!(entries) when is_list(entries),
    do: Enum.each(entries, &assert_key_entry!/1)

  defp assert_key_entries!(_), do: raise(ArgumentError, "key_entries_invalid")

  defp assert_key_entry!(entry) when is_map(entry) do
    keys = Enum.sort(Map.keys(entry))

    if keys not in [
         Enum.sort(["key_id", "key_material", "valid_from"]),
         Enum.sort(["key_id", "key_material", "valid_from", "revoked_at"])
       ],
       do: raise(ArgumentError, "key_entry_keys_invalid")

    if key_id!(entry["key_material"]) != entry["key_id"],
      do: raise(ArgumentError, "key_entry_key_id_mismatch")

    assert_persistent_key_entry_owner!(entry["key_material"])
    normalize_event_ref!(entry["valid_from"])

    if Map.has_key?(entry, "revoked_at"), do: normalize_event_ref!(entry["revoked_at"])

    :ok
  end

  defp assert_key_entry!(_), do: raise(ArgumentError, "key_entry_invalid")

  defp assert_persistent_key_entry_owner!(%{
         "protocol" => "refmd.hybrid-signing-key-material",
         "owner_kind" => "share_capability"
       }),
       do: raise(ArgumentError, "key_directory_share_capability_signer_persistent")

  defp assert_persistent_key_entry_owner!(%{
         "protocol" => "refmd.hybrid-signing-key-material",
         "owner_kind" => "invitation_redeem_authority"
       }),
       do: raise(ArgumentError, "key_directory_invitation_redeem_authority_signer_persistent")

  defp assert_persistent_key_entry_owner!(_material), do: :ok

  defp assert_revoked_key_ids!(key_ids) when is_list(key_ids) do
    if Enum.uniq(key_ids) != key_ids, do: raise(ArgumentError, "revoked_key_ids_duplicate")
    Enum.each(key_ids, &Hash.assert_blake3_base64url!/1)
  end

  defp assert_revoked_key_ids!(_), do: raise(ArgumentError, "revoked_key_ids_invalid")

  defp assert_event_body!(type, body), do: Body.assert!(type, body)

  defp normalize_event_ref!(ref) when is_map(ref) do
    assert_exact_keys!(ref, Enum.sort(["event_hash", "event_sequence", "scope_id", "scope_kind"]))
    assert_scope!(ref["scope_kind"], ref["scope_id"])
    assert_positive_integer!(ref["event_sequence"], "event_sequence_invalid")
    Hash.assert_blake3_base64url!(ref["event_hash"])
    ref
  end

  defp normalize_event_ref!(_), do: raise(ArgumentError, "event_ref_invalid")

  defp normalize_event_head!(head) when is_map(head) do
    assert_exact_keys!(head, Enum.sort(["head_hash", "head_sequence"]))
    assert_positive_integer!(head["head_sequence"], "event_head_sequence_invalid")
    Hash.assert_blake3_base64url!(head["head_hash"])
    head
  end

  defp normalize_event_head!(_), do: raise(ArgumentError, "event_head_invalid")

  defp assert_scope!(scope_kind, scope_id)
       when scope_kind in @valid_scope_kinds and is_binary(scope_id),
       do: :ok

  defp assert_scope!(_, _), do: raise(ArgumentError, "scope_invalid")

  defp assert_positive_integer!(value, _error)
       when is_integer(value) and value > 0 and value <= @max_safe_integer,
       do: :ok

  defp assert_positive_integer!(_, error), do: raise(ArgumentError, error)

  defp assert_iso8601!(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, _, _} -> :ok
      _ -> raise ArgumentError, "issued_at_invalid"
    end
  end

  defp assert_iso8601!(_), do: raise(ArgumentError, "issued_at_invalid")

  defp assert_literal!(value, value, _error), do: :ok
  defp assert_literal!(_, _, error), do: raise(ArgumentError, error)

  defp assert_exact_keys!(map, expected_keys) when is_map(map) do
    if Enum.sort(Map.keys(map)) == expected_keys do
      :ok
    else
      raise ArgumentError, "keys_invalid"
    end
  end
end
