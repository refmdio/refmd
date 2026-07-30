defmodule RefMD.Security.CompoundAppend do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Repo

  alias RefMD.Security.{
    AuditChainEvent,
    ConsumedCompoundIntentReceipt,
    PendingCompoundIntent
  }

  @intent_keys ~w(
    challenge_id compound_intent_id expires_at key_directory_effects_hash mutation_id
    protocol scopes version
  )
  @scope_keys ~w(
    candidate_event_head candidate_events candidate_key_directory_checkpoint_hash
    candidate_key_directory_checkpoint_payload candidate_key_directory_effects
    chain_scope_id chain_scope_kind checkpoint_payload_hash current_event_head
    effect_signature_requirements previous_signed_checkpoint required_checkpoint_variant
    scope_key_directory_effects_hash
  )
  @head_keys ~w(event_hash sequence)
  @effect_keys ~w(effect_order event_hash event_payload)
  @requirement_keys ~w(
    authorization_kind requirement_order signer_key_id signing_purpose subject_hash surface_variant
  )
  @pq_requirement_keys @requirement_keys ++
                         ~w(precommit_index precommit_kind pq_wrap_signing_input)
  @sorted_requirement_keys Enum.sort(@requirement_keys)
  @sorted_pq_requirement_keys Enum.sort(@pq_requirement_keys)
  @pq_wrap_signing_input_keys ~w(actor authority_boundary subject_hashes)
  @authorization_keys ~w(
    compound_intent_id effect_authorizations intent_hash mutation_id protocol scope_signatures version
  )
  @scope_signature_keys ~w(
    chain_scope_id chain_scope_kind checkpoint_hash checkpoint_variant signature
  )
  @effect_authorization_keys ~w(
    approval_proof authorization_kind requirement_order signature signer_key_id signing_purpose
    subject_hash surface_variant
  )
  @checkpoint_variants ~w(user_identity user_device workspace_device workspace_guest_device)
  @authorization_kinds ~w(
    device_approval device_revocation genesis_device_bootstrap key_directory_checkpoint
    key_directory_event pq_wrap
  )

  def persist_intent!(intent, command, attrs)
      when is_map(intent) and is_map(command) and is_map(attrs) do
    validate_intent!(intent)
    command_bytes = JCS.canonical_bytes!(command)
    intent_bytes = JCS.canonical_bytes!(intent)

    %PendingCompoundIntent{}
    |> PendingCompoundIntent.changeset(%{
      compound_intent_id: intent["compound_intent_id"],
      mutation_id: intent["mutation_id"],
      challenge_id: intent["challenge_id"],
      mutation_kind: Map.fetch!(attrs, :mutation_kind),
      actor_user_id: Map.fetch!(attrs, :actor_user_id),
      actor_device_id: Map.fetch!(attrs, :actor_device_id),
      command_jcs_b64u: Base.url_encode64(command_bytes, padding: false),
      command_hash: Hash.blake3_base64url(command_bytes),
      intent_jcs_b64u: Base.url_encode64(intent_bytes, padding: false),
      intent_hash: Hash.blake3_base64url(intent_bytes),
      expires_at: parse_timestamp!(intent["expires_at"]),
      created_at: Map.get(attrs, :created_at, DateTime.utc_now())
    })
    |> Repo.insert!()

    intent
  end

  def lock_intent!(compound_intent_id, mutation_id, now \\ DateTime.utc_now()) do
    pending =
      from(intent in PendingCompoundIntent,
        where:
          intent.compound_intent_id == ^compound_intent_id and
            intent.mutation_id == ^mutation_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    if is_nil(pending) or not is_nil(pending.consumed_at) or
         DateTime.compare(pending.expires_at, now) != :gt,
       do: invalid!("compound_intent_expired_or_consumed")

    intent = decode_canonical!(pending.intent_jcs_b64u, pending.intent_hash)
    command = decode_canonical!(pending.command_jcs_b64u, pending.command_hash)
    validate_intent!(intent)
    {pending, intent, command}
  end

  def replay_receipt(compound_intent_id, mutation_id, intent_hash, authorization_hash) do
    case Repo.get_by(ConsumedCompoundIntentReceipt,
           compound_intent_id: compound_intent_id,
           mutation_id: mutation_id
         ) do
      nil ->
        :not_found

      receipt ->
        if receipt.intent_hash == intent_hash and
             receipt.authorization_hash == authorization_hash do
          {:ok,
           %{
             status: receipt.response_status,
             content_type: receipt.response_content_type,
             body: decode_canonical!(receipt.response_body_jcs_b64u, receipt.response_hash)
           }}
        else
          invalid!("audit_checkpoint_intent_reuse")
        end
    end
  end

  def consume!(pending, intent, authorization, response, status, committed_at)
      when is_struct(pending, PendingCompoundIntent) and is_map(intent) and
             is_map(authorization) and is_map(response) do
    validate_authorization!(authorization, intent)
    response_bytes = JCS.canonical_bytes!(response)

    pending
    |> Ecto.Changeset.change(consumed_at: committed_at)
    |> Repo.update!()

    %ConsumedCompoundIntentReceipt{}
    |> ConsumedCompoundIntentReceipt.changeset(%{
      compound_intent_id: pending.compound_intent_id,
      mutation_id: pending.mutation_id,
      protocol: "refmd.audit.consumed-compound-intent-receipt",
      version: 1,
      intent_hash: hash(intent),
      authorization_hash: hash(authorization),
      response_status: status,
      response_content_type: "application/json",
      response_body_jcs_b64u: Base.url_encode64(response_bytes, padding: false),
      response_hash: Hash.blake3_base64url(response_bytes),
      committed_at: committed_at
    })
    |> Repo.insert!()
  end

  def validate_intent!(intent) when is_map(intent) do
    exact_keys!(intent, @intent_keys, "compound_intent_keys_invalid")
    literal!(intent["protocol"], "refmd.audit.compound-append-intent")
    literal!(intent["version"], 1)
    uuid!(intent["compound_intent_id"])
    uuid!(intent["mutation_id"])
    uuid!(intent["challenge_id"])
    future_timestamp!(intent["expires_at"])

    scopes = intent["scopes"]
    unless is_list(scopes) and scopes != [], do: invalid!("compound_intent_scopes_invalid")
    assert_scope_order!(scopes)
    Enum.each(scopes, &validate_scope!/1)

    expected_global_hash =
      scopes
      |> Enum.map(&global_effect_projection/1)
      |> then(&hash(%{"scopes" => &1}))

    literal!(intent["key_directory_effects_hash"], expected_global_hash)

    Enum.each(scopes, fn scope ->
      Enum.each(scope["candidate_events"], fn event ->
        literal!(event["event_body"]["key_directory_effects_hash"], expected_global_hash)
      end)
    end)

    intent
  end

  def validate_intent!(_), do: invalid!("compound_intent_invalid")

  def validate_authorization!(authorization, intent) when is_map(authorization) do
    validate_intent!(intent)
    exact_keys!(authorization, @authorization_keys, "compound_authorization_keys_invalid")
    literal!(authorization["protocol"], "refmd.audit.compound-append-authorization")
    literal!(authorization["version"], 1)
    literal!(authorization["compound_intent_id"], intent["compound_intent_id"])
    literal!(authorization["mutation_id"], intent["mutation_id"])
    literal!(authorization["intent_hash"], hash(intent))
    validate_scope_signatures!(authorization["scope_signatures"], intent["scopes"])
    validate_effect_authorizations!(authorization["effect_authorizations"], intent["scopes"])
    authorization
  end

  def validate_authorization!(_, _), do: invalid!("compound_authorization_invalid")

  def hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp validate_scope!(scope) do
    exact_keys!(scope, @scope_keys, "compound_intent_scope_keys_invalid")
    scope_kind!(scope["chain_scope_kind"])
    uuid!(scope["chain_scope_id"])
    head!(scope["current_event_head"], true)

    validate_previous_checkpoint!(
      scope["previous_signed_checkpoint"],
      scope["current_event_head"]
    )

    events!(scope)
    effects!(scope)
    requirements!(scope["effect_signature_requirements"])
    checkpoint!(scope)
  end

  defp events!(scope) do
    events = scope["candidate_events"]
    unless is_list(events) and events != [], do: invalid!("compound_intent_events_invalid")

    Enum.reduce(events, scope["current_event_head"], fn envelope, previous ->
      event = Map.drop(envelope, ["event_hash"])
      exact_keys!(envelope, AuditChainEvent.envelope_keys(), "compound_intent_event_keys_invalid")
      AuditChainEvent.assert_valid!(event)
      literal!(event["chain_scope_kind"], scope["chain_scope_kind"])
      literal!(event["chain_scope_id"], scope["chain_scope_id"])
      literal!(event["sequence"], previous["sequence"] + 1)
      literal!(event["previous_event_hash"], previous["event_hash"])
      literal!(envelope["event_hash"], AuditChainEvent.hash!(event))
      %{"sequence" => event["sequence"], "event_hash" => envelope["event_hash"]}
    end)
    |> then(&literal!(scope["candidate_event_head"], &1))
  end

  defp effects!(scope) do
    effects = scope["candidate_key_directory_effects"]
    unless is_list(effects), do: invalid!("compound_intent_effects_invalid")

    Enum.with_index(effects, 1)
    |> Enum.each(fn {effect, order} ->
      exact_keys!(effect, @effect_keys, "compound_intent_effect_keys_invalid")
      literal!(effect["effect_order"], order)
      literal!(effect["event_hash"], KeyDirectory.event_hash(effect["event_payload"]))
    end)

    literal!(scope["scope_key_directory_effects_hash"], hash(scope_effect_projection(scope)))
  end

  defp checkpoint!(%{"candidate_key_directory_checkpoint_payload" => "UNCHANGED"} = scope) do
    literal!(scope["candidate_key_directory_checkpoint_hash"], "UNCHANGED")
  end

  defp checkpoint!(scope) do
    payload = scope["candidate_key_directory_checkpoint_payload"]
    checkpoint_hash = KeyDirectory.checkpoint_hash(payload)
    literal!(scope["candidate_key_directory_checkpoint_hash"], checkpoint_hash)

    variant = scope["required_checkpoint_variant"]

    unless variant in @checkpoint_variants,
      do: invalid!("compound_intent_checkpoint_variant_invalid")

    Hash.assert_blake3_base64url!(scope["checkpoint_payload_hash"])
  end

  defp requirements!(requirements) when is_list(requirements) do
    Enum.with_index(requirements, 1)
    |> Enum.each(fn {requirement, order} ->
      requirement_keys = requirement_keys(requirement)

      exact_keys!(requirement, requirement_keys, "compound_intent_requirement_keys_invalid")
      literal!(requirement["requirement_order"], order)

      unless requirement["authorization_kind"] in @authorization_kinds,
        do: invalid!("compound_intent_authorization_kind_invalid")

      Hash.assert_blake3_base64url!(requirement["subject_hash"])
      Hash.assert_blake3_base64url!(requirement["signer_key_id"])
      validate_pq_requirement!(requirement)
    end)
  end

  defp requirements!(_), do: invalid!("compound_intent_requirements_invalid")

  defp requirement_keys(%{"authorization_kind" => "pq_wrap"} = requirement) do
    case Enum.sort(Map.keys(requirement)) do
      @sorted_requirement_keys -> @requirement_keys
      @sorted_pq_requirement_keys -> @pq_requirement_keys
      _ -> @pq_requirement_keys
    end
  end

  defp requirement_keys(_requirement), do: @requirement_keys

  defp validate_pq_requirement!(%{"authorization_kind" => "pq_wrap"} = requirement) do
    if Enum.sort(Map.keys(requirement)) == @sorted_requirement_keys,
      do: :ok,
      else: validate_kek_pq_requirement!(requirement)
  end

  defp validate_pq_requirement!(_), do: :ok

  defp validate_kek_pq_requirement!(requirement) do
    unless requirement["precommit_kind"] in ["device_wrap", "member_envelope"],
      do: invalid!("compound_intent_pq_precommit_kind_invalid")

    unless is_integer(requirement["precommit_index"]) and requirement["precommit_index"] >= 0,
      do: invalid!("compound_intent_pq_precommit_index_invalid")

    input = requirement["pq_wrap_signing_input"]

    unless is_map(input), do: invalid!("compound_intent_pq_signing_input_invalid")

    exact_keys!(
      input,
      @pq_wrap_signing_input_keys,
      "compound_intent_pq_signing_input_keys_invalid"
    )

    Enum.each(@pq_wrap_signing_input_keys, fn key ->
      unless is_map(input[key]), do: invalid!("compound_intent_pq_signing_input_invalid")
    end)
  end

  defp validate_scope_signatures!(signatures, scopes)
       when is_list(signatures) and length(signatures) == length(scopes) do
    Enum.zip(signatures, scopes)
    |> Enum.each(fn {signature, scope} ->
      exact_keys!(signature, @scope_signature_keys, "compound_scope_signature_keys_invalid")
      literal!(signature["chain_scope_kind"], scope["chain_scope_kind"])
      literal!(signature["chain_scope_id"], scope["chain_scope_id"])
      literal!(signature["checkpoint_hash"], scope["checkpoint_payload_hash"])
      literal!(signature["checkpoint_variant"], scope["required_checkpoint_variant"])
      unless is_map(signature["signature"]), do: invalid!("compound_scope_signature_invalid")
    end)
  end

  defp validate_scope_signatures!(_, _), do: invalid!("compound_scope_signatures_invalid")

  defp validate_effect_authorizations!(authorizations, scopes) when is_list(authorizations) do
    requirements = Enum.flat_map(scopes, & &1["effect_signature_requirements"])

    unless length(authorizations) == length(requirements),
      do: invalid!("compound_effect_authorizations_invalid")

    Enum.zip(authorizations, requirements)
    |> Enum.each(fn {authorization, requirement} ->
      exact_keys!(
        authorization,
        @effect_authorization_keys,
        "compound_effect_authorization_keys_invalid"
      )

      Enum.each(@requirement_keys, fn key -> literal!(authorization[key], requirement[key]) end)

      unless is_map(authorization["signature"]),
        do: invalid!("compound_effect_authorization_signature_invalid")

      validate_approval_proof!(authorization)
    end)
  end

  defp validate_effect_authorizations!(_, _),
    do: invalid!("compound_effect_authorizations_invalid")

  defp validate_approval_proof!(%{
         "authorization_kind" => "device_approval",
         "approval_proof" => proof
       })
       when is_map(proof),
       do: :ok

  defp validate_approval_proof!(%{
         "authorization_kind" => kind,
         "approval_proof" => "NONE"
       })
       when kind != "device_approval",
       do: :ok

  defp validate_approval_proof!(_), do: invalid!("compound_effect_approval_proof_invalid")

  defp scope_effect_projection(scope) do
    %{
      "candidate_key_directory_effects" => scope["candidate_key_directory_effects"],
      "candidate_key_directory_checkpoint_payload" =>
        scope["candidate_key_directory_checkpoint_payload"],
      "candidate_key_directory_checkpoint_hash" =>
        scope["candidate_key_directory_checkpoint_hash"]
    }
  end

  defp global_effect_projection(scope) do
    %{
      "chain_scope_kind" => scope["chain_scope_kind"],
      "chain_scope_id" => scope["chain_scope_id"],
      "events" => Enum.map(scope["candidate_key_directory_effects"], & &1["event_payload"]),
      "checkpoint" => scope["candidate_key_directory_checkpoint_payload"]
    }
  end

  defp assert_scope_order!(scopes) do
    order = Enum.map(scopes, &{&1["chain_scope_kind"], &1["chain_scope_id"]})
    expected = Enum.sort_by(order, fn {kind, id} -> {if(kind == "user", do: 0, else: 1), id} end)
    literal!(order, expected)
    if length(order) != length(Enum.uniq(order)), do: invalid!("compound_intent_scope_duplicate")
  end

  defp validate_previous_checkpoint!("GENESIS", %{"sequence" => 0, "event_hash" => "GENESIS"}),
    do: :ok

  defp validate_previous_checkpoint!(
         %{"sequence" => sequence, "checkpoint_hash" => hash},
         %{"sequence" => head_sequence}
       )
       when is_integer(sequence) and sequence > 0 and head_sequence > 0 do
    Hash.assert_blake3_base64url!(hash)
  end

  defp validate_previous_checkpoint!(_, _),
    do: invalid!("compound_intent_previous_checkpoint_invalid")

  defp head!(head, allow_genesis?) do
    exact_keys!(head, @head_keys, "compound_intent_head_keys_invalid")

    case head do
      %{"sequence" => 0, "event_hash" => "GENESIS"} when allow_genesis? ->
        :ok

      %{"sequence" => sequence, "event_hash" => hash}
      when is_integer(sequence) and sequence > 0 ->
        Hash.assert_blake3_base64url!(hash)

      _ ->
        invalid!("compound_intent_head_invalid")
    end
  end

  defp scope_kind!(kind) when kind in ["user", "workspace"], do: :ok
  defp scope_kind!(_), do: invalid!("compound_intent_scope_kind_invalid")

  defp future_timestamp!(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, _datetime, 0} -> :ok
      _ -> invalid!("compound_intent_expiry_invalid")
    end
  end

  defp future_timestamp!(_), do: invalid!("compound_intent_expiry_invalid")

  defp parse_timestamp!(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, 0} -> datetime
      _ -> invalid!("compound_intent_expiry_invalid")
    end
  end

  defp decode_canonical!(encoded, expected_hash) do
    with {:ok, bytes} <- Base.url_decode64(encoded, padding: false),
         ^expected_hash <- Hash.blake3_base64url(bytes) do
      value = JCS.parse_json_strict!(bytes)
      literal!(JCS.canonical_bytes!(value), bytes)
      value
    else
      _ -> invalid!("compound_intent_persistence_invalid")
    end
  end

  defp uuid!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, ^value} -> :ok
      _ -> invalid!("compound_intent_uuid_invalid")
    end
  end

  defp exact_keys!(value, keys, error) when is_map(value) do
    unless Enum.sort(Map.keys(value)) == Enum.sort(keys), do: invalid!(error)
  end

  defp exact_keys!(_, _, error), do: invalid!(error)

  defp literal!(actual, expected) do
    unless actual == expected, do: invalid!("compound_intent_binding_invalid")
  end

  defp invalid!(message), do: raise(ArgumentError, message)
end
