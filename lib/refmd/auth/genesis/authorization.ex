defmodule RefMD.Auth.Genesis.Authorization do
  @moduledoc false

  alias RefMD.Auth.Genesis.{Intent, Prepare}
  alias RefMD.Auth.{PendingAccountGenesis, PendingGenesisChallenge, PendingGenesisIntent}
  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Security.CompoundAppend

  @keys ~w(compound_intent_id effect_authorizations intent_hash mutation_id protocol scope_signatures version)
  @scope_signature_keys ~w(chain_scope_id chain_scope_kind checkpoint_hash checkpoint_variant signature)
  @authorization_keys ~w(approval_proof authorization_kind requirement_order signature signer_key_id signing_purpose subject_hash surface_variant)

  def verify!(
        %PendingAccountGenesis{} = genesis,
        %PendingGenesisChallenge{} = challenge,
        %PendingGenesisIntent{} = pending,
        authorization
      )
      when is_map(authorization) do
    exact_keys!(authorization, @keys)
    literal!(authorization["protocol"], "refmd.audit.compound-append-authorization")
    literal!(authorization["version"], 1)
    literal!(authorization["compound_intent_id"], pending.compound_intent_id)
    literal!(authorization["mutation_id"], pending.mutation_id)

    prepare = decode_canonical!(pending.prepare_request_jcs_b64u)
    intent = decode_canonical!(pending.compound_intent_jcs_b64u)
    literal!(hash(prepare), pending.prepare_request_hash)
    literal!(hash(intent), pending.intent_hash)
    literal!(authorization["intent_hash"], pending.intent_hash)
    CompoundAppend.validate_authorization!(authorization, intent)
    prepared = Prepare.validate!(genesis, prepare)

    verify_intent!(intent, pending)
    verify_scope_signatures!(authorization["scope_signatures"], intent, prepare)

    verify_effect_authorizations!(
      authorization["effect_authorizations"],
      intent,
      prepare,
      prepared,
      genesis,
      challenge
    )

    %{authorization: authorization, intent: intent, prepare: prepare, prepared: prepared}
  end

  def verify!(_, _, _, _), do: raise(ArgumentError, "genesis_authorization_invalid")

  defp verify_intent!(intent, pending) do
    exact_keys!(
      intent,
      ~w(challenge_id compound_intent_id expires_at key_directory_effects_hash mutation_id protocol scopes version)
    )

    literal!(intent["protocol"], "refmd.audit.compound-append-intent")
    literal!(intent["version"], 1)
    literal!(intent["compound_intent_id"], pending.compound_intent_id)
    literal!(intent["mutation_id"], pending.mutation_id)
    literal!(intent["challenge_id"], pending.registration_id)
    literal!(intent["expires_at"], DateTime.to_iso8601(pending.expires_at))

    case intent["scopes"] do
      [%{"chain_scope_kind" => "user"}, %{"chain_scope_kind" => "workspace"}] -> :ok
      _ -> raise ArgumentError, "genesis_intent_scope_order_invalid"
    end
  end

  defp verify_scope_signatures!(signatures, intent, prepare)
       when is_list(signatures) and length(signatures) == 2 do
    Enum.zip(signatures, intent["scopes"])
    |> Enum.each(fn {entry, scope} ->
      exact_keys!(entry, @scope_signature_keys)
      variant = scope["required_checkpoint_variant"]
      payload = audit_checkpoint_payload(scope, prepare, variant)
      checkpoint_hash = Audit.checkpoint_hash!(variant, payload)
      literal!(entry["chain_scope_kind"], scope["chain_scope_kind"])
      literal!(entry["chain_scope_id"], scope["chain_scope_id"])
      literal!(entry["checkpoint_hash"], checkpoint_hash)
      literal!(entry["checkpoint_hash"], scope["checkpoint_payload_hash"])
      literal!(entry["checkpoint_variant"], variant)

      {owner_kind, owner_id, material} = signing_material(variant, prepare)

      transcript =
        Audit.build_audit_checkpoint_transcript!(variant, owner_kind, owner_id, payload)

      verify_signature!("audit_checkpoint", transcript, entry["signature"], material)
    end)
  end

  defp verify_scope_signatures!(_, _, _),
    do: raise(ArgumentError, "genesis_scope_signatures_invalid")

  defp verify_effect_authorizations!(entries, intent, prepare, prepared, genesis, challenge)
       when is_list(entries) do
    requirements = Enum.flat_map(intent["scopes"], & &1["effect_signature_requirements"])

    unless length(entries) == length(requirements),
      do: raise(ArgumentError, "genesis_effect_authorization_count_invalid")

    scope_entries =
      intent["scopes"]
      |> Enum.flat_map(fn scope ->
        Enum.map(scope["effect_signature_requirements"], &{scope, &1})
      end)

    Enum.zip(entries, scope_entries)
    |> Enum.each(fn {entry, {scope, requirement}} ->
      exact_keys!(entry, @authorization_keys)

      Enum.each(
        ~w(authorization_kind requirement_order signer_key_id signing_purpose subject_hash surface_variant),
        &literal!(entry[&1], requirement[&1])
      )

      literal!(entry["approval_proof"], "NONE")

      {transcript, material} =
        effect_transcript!(scope, requirement, intent, prepare, prepared, genesis, challenge)

      literal!(hash(transcript), requirement["subject_hash"])
      verify_signature!(requirement["signing_purpose"], transcript, entry["signature"], material)
    end)
  end

  defp verify_effect_authorizations!(_, _, _, _, _, _),
    do: raise(ArgumentError, "genesis_effect_authorizations_invalid")

  defp effect_transcript!(
         scope,
         %{"authorization_kind" => "key_directory_event"} = req,
         _intent,
         prepare,
         _prepared,
         _genesis,
         _challenge
       ) do
    effect = Enum.at(scope["candidate_key_directory_effects"], req["requirement_order"] - 1)
    payload = effect["event_payload"]
    literal!(effect["event_hash"], KeyDirectory.event_hash(payload))
    {owner_kind, owner_id, material} = effect_signer(scope, prepare)

    {Signature.build_key_directory_event_transcript!(
       payload["event_type"],
       owner_kind,
       owner_id,
       payload
     ), material}
  end

  defp effect_transcript!(
         scope,
         %{"authorization_kind" => "key_directory_checkpoint"},
         _intent,
         prepare,
         _prepared,
         _genesis,
         _challenge
       ) do
    payload = scope["candidate_key_directory_checkpoint_payload"]

    literal!(
      scope["candidate_key_directory_checkpoint_hash"],
      KeyDirectory.checkpoint_hash(payload)
    )

    {owner_kind, owner_id, material} = effect_signer(scope, prepare)
    signer = checkpoint_signer(owner_kind, prepare)

    {Signature.build_key_directory_checkpoint_transcript!(
       scope_checkpoint_variant(scope),
       owner_kind,
       owner_id,
       payload,
       signer
     ), material}
  end

  defp effect_transcript!(
         scope,
         %{"authorization_kind" => "pq_wrap"},
         _intent,
         prepare,
         prepared,
         _genesis,
         _challenge
       ) do
    event = List.last(scope["candidate_key_directory_effects"])["event_payload"]
    event_hash = KeyDirectory.event_hash(event)
    checkpoint_hash = scope["candidate_key_directory_checkpoint_hash"]
    member = prepared.member_envelope
    wrap = prepare["workspace_member_envelope_precommit"]["wrap"]

    transcript =
      Signature.build_pq_wrap_transcript!(
        prepare["device_id"],
        wrap["sender"],
        %{
          "scope_kind" => "workspace",
          "scope_id" => prepare["workspace_id"],
          "event_hash" => event_hash,
          "operation_checkpoint_sequence" => 1,
          "operation_checkpoint_hash" => checkpoint_hash,
          "covered_event_head_sequence" => event["sequence"],
          "covered_event_head_hash" => event_hash
        },
        %{
          "resource_hash" => member.resource_hash,
          "wrap_body_hash" => member.wrap_body_hash,
          "wrap_event_body_hash" => hash(event["body"]),
          "wrap_event_hash" => event_hash,
          "hpke_info_hash" => member.hpke_info_hash,
          "aad_hash" => member.aad_hash
        },
        "workspace_genesis"
      )

    {transcript, prepare["device_hybrid_signing_public_key_material"]}
  end

  defp effect_transcript!(
         _scope,
         %{"authorization_kind" => "genesis_device_bootstrap"},
         intent,
         prepare,
         prepared,
         genesis,
         challenge
       ) do
    [user_scope, workspace_scope] = intent["scopes"]
    user_device = find_effect!(user_scope, "device_key_added")
    workspace_device = find_effect!(workspace_scope, "device_key_added")
    owner_member = find_effect!(workspace_scope, "member_added")

    links = %{
      user_device_key_added_event_hash: user_device["event_hash"],
      workspace_device_key_added_event_hash: workspace_device["event_hash"],
      owner_user_id: prepare["user_id"],
      owner_role_id: prepare["owner_role_id"],
      owner_member_added_event_hash: owner_member["event_hash"],
      workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash
    }

    context_hash =
      Intent.compound_context_hash!(
        genesis.registration_id,
        prepared.prepare_request_hash,
        intent,
        links
      )

    transcript =
      Signature.build_genesis_device_bootstrap_transcript!(%{
        registration_id: genesis.registration_id,
        compound_intent_id: intent["compound_intent_id"],
        mutation_id: intent["mutation_id"],
        genesis_compound_context_hash: context_hash,
        user_id: prepare["user_id"],
        workspace_id: prepare["workspace_id"],
        owner_role_id: prepare["owner_role_id"],
        device_id: prepare["device_id"],
        device_public_material: prepare["device_hybrid_signing_public_key_material"],
        device_hybrid_encryption_public_key_material:
          prepare["device_hybrid_encryption_public_key_material"],
        client_nonce: prepare["client_nonce"],
        registration_challenge_hash: challenge.challenge_hash,
        identity_signing_key_id: prepared.identity_signing_key_id,
        user_identity_public_key_hash:
          hash(prepare["identity_hybrid_signing_public_key_material"]),
        user_device_key_added_event_hash: user_device["event_hash"],
        workspace_device_key_added_event_hash: workspace_device["event_hash"],
        owner_member_added_event_hash: owner_member["event_hash"],
        workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash,
        user_audit_checkpoint: %{
          "sequence" => 2,
          "checkpoint_hash" => user_scope["checkpoint_payload_hash"]
        },
        workspace_audit_checkpoint: %{
          "sequence" => 1,
          "checkpoint_hash" => workspace_scope["checkpoint_payload_hash"]
        }
      })

    {transcript, prepare["identity_hybrid_signing_public_key_material"]}
  end

  defp effect_transcript!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "genesis_effect_authorization_kind_invalid")

  defp audit_checkpoint_payload(scope, prepare, variant) do
    event = List.last(scope["candidate_events"])

    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => scope["chain_scope_kind"],
      "chain_scope_id" => scope["chain_scope_id"],
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => prepare["user_id"],
      "signing_key_id" =>
        if(variant == "user_identity",
          do: prepare["identity_signing_key_id"],
          else: prepare["device_signing_key_id"]
        ),
      "authorization_checkpoint_scope_kind" => scope["chain_scope_kind"],
      "authorization_checkpoint_scope_id" => scope["chain_scope_id"],
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => event["event_type"]
    }
    |> maybe_put(
      "signer_device_id",
      if(variant == "user_identity", do: nil, else: prepare["device_id"])
    )
  end

  defp signing_material("user_identity", prepare),
    do: {"identity", prepare["user_id"], prepare["identity_hybrid_signing_public_key_material"]}

  defp signing_material("workspace_device", prepare),
    do: {"device", prepare["device_id"], prepare["device_hybrid_signing_public_key_material"]}

  defp effect_signer(%{"chain_scope_kind" => "user"}, prepare),
    do: signing_material("user_identity", prepare)

  defp effect_signer(%{"chain_scope_kind" => "workspace"}, prepare),
    do: signing_material("workspace_device", prepare)

  defp checkpoint_signer("identity", prepare),
    do: %{
      "signer_kind" => "identity",
      "user_id" => prepare["user_id"],
      "signing_key_id" => prepare["identity_signing_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

  defp checkpoint_signer("device", prepare),
    do: %{
      "signer_kind" => "device",
      "user_id" => prepare["user_id"],
      "device_id" => prepare["device_id"],
      "signing_key_id" => prepare["device_signing_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

  defp scope_checkpoint_variant(%{"chain_scope_kind" => "user"}), do: "identity_initial"
  defp scope_checkpoint_variant(%{"chain_scope_kind" => "workspace"}), do: "workspace_initial"

  defp find_effect!(scope, event_type) do
    Enum.find(scope["candidate_key_directory_effects"], fn effect ->
      effect["event_payload"]["event_type"] == event_type
    end) || raise(ArgumentError, "genesis_effect_missing")
  end

  defp verify_signature!(purpose, transcript, signature, material) do
    case Signature.verify_hybrid_signature_result(purpose, transcript, signature, material) do
      :ok -> :ok
      {:error, _} -> raise ArgumentError, "genesis_effect_signature_invalid"
    end
  end

  defp decode_canonical!(encoded) do
    bytes = Base.url_decode64!(encoded, padding: false)
    decoded = Jason.decode!(bytes)
    literal!(JCS.canonical_bytes!(decoded), bytes)
    decoded
  end

  defp exact_keys!(value, keys) when is_map(value) do
    unless Enum.sort(Map.keys(value)) == Enum.sort(keys),
      do: raise(ArgumentError, "genesis_authorization_keys_invalid")
  end

  defp exact_keys!(_, _), do: raise(ArgumentError, "genesis_authorization_invalid")
  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp literal!(value, value), do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "genesis_authorization_binding_mismatch")
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
