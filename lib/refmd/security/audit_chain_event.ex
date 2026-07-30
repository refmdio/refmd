defmodule RefMD.Security.AuditChainEvent do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}

  @keys ~w(
    chain_scope_id
    chain_scope_kind
    event_body
    event_id
    event_type
    previous_event_hash
    protocol
    sequence
    version
  )
  @high_risk_event_types MapSet.new(~w(
    user.account.genesis user.device.genesis_bootstrapped user.device.approved
    user.device.recovery_approved user.device.revoked.security
    workspace.security_device_revocation.applied user.device.revoked.retire
    user.identity.key_added user.identity.signing_key_revoked
    user.identity.encryption_key_revoked user.identity.rotation_started
    user.identity.rotation_completed workspace.identity_self_envelope_rewrap.completed
    user.identity.old_key_deleted user.recovery_authorization.created
    user.recovery_authorization.replaced user.trust_transfer.completed
    user.suite_policy.changed workspace.genesis workspace.member.added
    workspace.member.removed workspace.member.role_changed workspace.invitation.created
    workspace.invitation.redeemed.known_recipient
    workspace.invitation.redeemed.unknown_recipient workspace.invitation.revoked
    workspace.guest_invitation.created
    workspace.guest_invitation.redeemed.known_recipient
    workspace.guest_invitation.redeemed.unknown_recipient
    workspace.guest_invitation.revoked workspace.guest_grant.revoked
    workspace.guest_device.revoked workspace.share.created
    workspace.share.metadata_updated workspace.share.key_scope_added
    workspace.share.key_scope_replaced workspace.share.key_scope_removed
    workspace.share.exclusion_changed workspace.share.revoked
    workspace.kek.rotation_started workspace.kek.rotation_completed
    workspace.kek.old_key_deleted workspace.dek.rotation_started
    workspace.dek.rotation_completed workspace.dek.old_key_deleted
    workspace.suite_policy.changed
  ))
  @runtime_body_keys ~w(
    action actor class correlation created_at event_id protocol resource scope sensitivity type version
  )

  def build!(attrs) when is_map(attrs) do
    event = %{
      "protocol" => "refmd.audit.chain-event",
      "version" => 1,
      "event_id" => fetch_any!(attrs, ["event_id", "id"]),
      "chain_scope_kind" => fetch!(attrs, "chain_scope_kind"),
      "chain_scope_id" => fetch!(attrs, "chain_scope_id"),
      "sequence" => fetch!(attrs, "sequence"),
      "previous_event_hash" => fetch!(attrs, "previous_event_hash"),
      "event_type" => fetch_any!(attrs, ["event_type", "type"]),
      "event_body" => fetch!(attrs, "event_body")
    }

    assert_valid!(event)
    event
  end

  def hash!(event) when is_map(event) do
    event
    |> assert_valid!()
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  def envelope!(event, event_hash) when is_map(event) and is_binary(event_hash) do
    Hash.assert_blake3_base64url!(event_hash)
    Map.put(assert_valid!(event), "event_hash", event_hash)
  end

  def envelope_keys, do: ["event_hash" | @keys]

  def high_risk_event_type?(event_type) when is_binary(event_type),
    do: MapSet.member?(@high_risk_event_types, event_type)

  def high_risk_event_type?(_), do: false

  def assert_valid!(event) when is_map(event) do
    unless Enum.sort(Map.keys(event)) == @keys,
      do: raise(ArgumentError, "audit_chain_event_keys_invalid")

    assert_literal!(event["protocol"], "refmd.audit.chain-event")
    assert_literal!(event["version"], 1)
    assert_uuid!(event["event_id"])
    assert_uuid!(event["chain_scope_id"])

    unless event["chain_scope_kind"] in ["user", "workspace"],
      do: raise(ArgumentError, "audit_chain_event_scope_invalid")

    unless is_integer(event["sequence"]) and event["sequence"] > 0,
      do: raise(ArgumentError, "audit_chain_event_sequence_invalid")

    assert_predecessor!(event["sequence"], event["previous_event_hash"])
    assert_non_empty!(event["event_type"], "audit_chain_event_type_invalid")

    unless is_map(event["event_body"]),
      do: raise(ArgumentError, "audit_chain_event_body_invalid")

    assert_body_binding!(event)
    event
  end

  def assert_valid!(_), do: raise(ArgumentError, "audit_chain_event_invalid")

  defp assert_body_binding!(%{"event_body" => body} = event) do
    high_risk? = MapSet.member?(@high_risk_event_types, event["event_type"])

    case {high_risk?, body["protocol"]} do
      {true, "refmd.audit.high-risk-mutation"} -> assert_high_risk_body!(event, body)
      {false, "refmd.security-audit-event"} -> assert_runtime_body!(event, body)
      _ -> raise ArgumentError, "audit_chain_event_body_protocol_invalid"
    end
  end

  defp assert_runtime_body!(event, body) do
    assert_exact_keys!(body, @runtime_body_keys, "audit_chain_event_body_keys_invalid")
    assert_literal!(body["protocol"], "refmd.security-audit-event")
    assert_literal!(body["version"], 1)
    assert_literal!(event["event_id"], event["event_body"]["event_id"])
    assert_literal!(event["event_type"], event["event_body"]["type"])
    assert_in!(body["class"], ["authority", "security_runtime"])
    assert_iso8601!(body["created_at"])

    assert_nullable_record!(
      body["actor"],
      ~w(device_id principal_id session_id user_id),
      ~w(principal_kind)
    )

    assert_in!(body["actor"]["principal_kind"], ~w(user share_participant system worker))
    assert_nullable_record!(body["scope"], ~w(document_id share_id workspace_id), [])
    assert_nullable_record!(body["resource"], ~w(version_hash), ~w(id kind))

    assert_in!(
      body["resource"]["kind"],
      ~w(plugin device document workspace share credential network_endpoint)
    )

    assert_nullable_record!(body["action"], ~w(reason_code), ~w(operation result))
    assert_in!(body["action"]["result"], ~w(allowed denied failed completed))

    assert_nullable_record!(
      body["correlation"],
      ~w(authority_event_ref capability_id execution_context_id request_id),
      []
    )

    sensitivity = body["sensitivity"]

    assert_exact_keys!(
      sensitivity,
      ~w(egress_bytes plaintext_bytes plaintext_scope_kind storage_bytes),
      "audit_chain_event_sensitivity_invalid"
    )

    assert_in!(
      sensitivity["plaintext_scope_kind"],
      ~w(none selection block active_document selected_documents workspace)
    )

    Enum.each(~w(egress_bytes plaintext_bytes storage_bytes), fn key ->
      assert_non_negative_integer!(sensitivity[key])
    end)
  end

  defp assert_high_risk_body!(event, body) do
    assert_exact_keys!(
      body,
      ~w(actor canonical_request_hash chain_scope_id chain_scope_kind event_type
         key_directory_effects_hash mutation_id protocol subject_id subject_kind version),
      "audit_chain_event_body_keys_invalid"
    )

    assert_literal!(body["protocol"], "refmd.audit.high-risk-mutation")
    assert_literal!(body["version"], 1)
    assert_literal!(event["event_type"], body["event_type"])
    assert_literal!(event["chain_scope_kind"], body["chain_scope_kind"])
    assert_literal!(event["chain_scope_id"], body["chain_scope_id"])
    assert_uuid!(body["mutation_id"])
    assert_non_empty!(body["subject_kind"], "audit_chain_event_subject_invalid")
    assert_non_empty!(body["subject_id"], "audit_chain_event_subject_invalid")
    Hash.assert_blake3_base64url!(body["canonical_request_hash"])
    Hash.assert_blake3_base64url!(body["key_directory_effects_hash"])
    assert_high_risk_actor!(body["actor"])
  end

  defp assert_high_risk_actor!(%{"kind" => "identity"} = actor) do
    assert_exact_keys!(actor, ~w(kind user_id), "audit_chain_event_actor_invalid")
    assert_uuid!(actor["user_id"])
  end

  defp assert_high_risk_actor!(%{"kind" => "device"} = actor) do
    assert_exact_keys!(actor, ~w(device_id kind user_id), "audit_chain_event_actor_invalid")
    assert_uuid!(actor["user_id"])
    assert_uuid!(actor["device_id"])
  end

  defp assert_high_risk_actor!(_),
    do: raise(ArgumentError, "audit_chain_event_actor_invalid")

  defp assert_nullable_record!(value, nullable_keys, required_keys) when is_map(value) do
    assert_exact_keys!(
      value,
      nullable_keys ++ required_keys,
      "audit_chain_event_body_keys_invalid"
    )

    Enum.each(nullable_keys, fn key ->
      if not is_nil(value[key]),
        do: assert_non_empty!(value[key], "audit_chain_event_body_invalid")
    end)

    Enum.each(required_keys, fn key ->
      assert_non_empty!(value[key], "audit_chain_event_body_invalid")
    end)
  end

  defp assert_nullable_record!(_, _, _),
    do: raise(ArgumentError, "audit_chain_event_body_invalid")

  defp assert_exact_keys!(value, keys, error) when is_map(value) do
    unless Enum.sort(Map.keys(value)) == Enum.sort(keys), do: raise(ArgumentError, error)
  end

  defp assert_exact_keys!(_, _, error), do: raise(ArgumentError, error)

  defp assert_in!(value, values) do
    unless value in values, do: raise(ArgumentError, "audit_chain_event_body_invalid")
  end

  defp assert_iso8601!(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, _datetime, 0} -> :ok
      _ -> raise ArgumentError, "audit_chain_event_created_at_invalid"
    end
  end

  defp assert_iso8601!(_), do: raise(ArgumentError, "audit_chain_event_created_at_invalid")

  defp assert_non_negative_integer!(value) when is_integer(value) and value >= 0, do: :ok

  defp assert_non_negative_integer!(_),
    do: raise(ArgumentError, "audit_chain_event_sensitivity_invalid")

  defp assert_predecessor!(1, "GENESIS"), do: :ok

  defp assert_predecessor!(sequence, predecessor) when sequence > 1 do
    Hash.assert_blake3_base64url!(predecessor)
  end

  defp assert_predecessor!(_, _),
    do: raise(ArgumentError, "audit_chain_event_predecessor_invalid")

  defp assert_uuid!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, ^value} -> :ok
      _ -> raise ArgumentError, "audit_chain_event_uuid_invalid"
    end
  end

  defp assert_non_empty!(value, _error) when is_binary(value) and value != "", do: :ok
  defp assert_non_empty!(_, error), do: raise(ArgumentError, error)

  defp assert_literal!(value, value), do: :ok
  defp assert_literal!(_, _), do: raise(ArgumentError, "audit_chain_event_binding_invalid")

  defp fetch!(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.fetch!(attrs, String.to_existing_atom(key))
    end
  end

  defp fetch_any!(attrs, keys) do
    Enum.find_value(keys, fn key ->
      case Map.fetch(attrs, key) do
        {:ok, value} -> value
        :error -> Map.get(attrs, String.to_existing_atom(key))
      end
    end) || raise KeyError, key: hd(keys), term: attrs
  end
end
