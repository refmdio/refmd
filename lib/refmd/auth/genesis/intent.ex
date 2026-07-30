defmodule RefMD.Auth.Genesis.Intent do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.Genesis.Prepare
  alias RefMD.Auth.{PendingAccountGenesis, PendingGenesisChallenge, PendingGenesisIntent}
  alias RefMD.Crypto.{Hash, JCS, Signature, Suite}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Payload
  alias RefMD.Repo
  alias RefMD.Security.AuditChainEvent

  @protocol "refmd.audit.compound-append-intent"
  @version 1

  def issue!(%PendingAccountGenesis{} = genesis, session, params) when is_map(params) do
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      challenge = lock_challenge!(genesis, session, params, now)
      prepared = Prepare.validate!(genesis, params)

      case lock_existing(genesis.registration_id) do
        %PendingGenesisIntent{} = existing ->
          return_existing!(existing, prepared.prepare_request_hash, now)

        nil ->
          build_and_insert!(genesis, challenge, prepared, now)
      end
    end)
    |> case do
      {:ok, intent} -> {:ok, intent}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error in ArgumentError -> {:error, error.message}
    error in Ecto.InvalidChangesetError -> {:error, error.changeset}
  end

  def issue!(_, _, _), do: {:error, :invalid_genesis_intent}

  def compound_context!(registration_id, prepare_request_hash, intent, links)
      when is_binary(registration_id) and is_binary(prepare_request_hash) and is_map(intent) and
             is_map(links) do
    scopes = Map.fetch!(intent, "scopes")

    unless length(scopes) == 2,
      do: raise(ArgumentError, "genesis_compound_context_scopes_invalid")

    %{
      "protocol" => "refmd.genesis-compound-authorization-context",
      "version" => 1,
      "registration_id" => registration_id,
      "compound_intent_id" => Map.fetch!(intent, "compound_intent_id"),
      "mutation_id" => Map.fetch!(intent, "mutation_id"),
      "challenge_id" => Map.fetch!(intent, "challenge_id"),
      "expires_at" => Map.fetch!(intent, "expires_at"),
      "prepare_request_hash" => prepare_request_hash,
      "key_directory_effects_hash" => Map.fetch!(intent, "key_directory_effects_hash"),
      "scopes" => Enum.map(scopes, &compound_context_scope!/1),
      "user_device_key_added_event_hash" => Map.fetch!(links, :user_device_key_added_event_hash),
      "workspace_device_key_added_event_hash" =>
        Map.fetch!(links, :workspace_device_key_added_event_hash),
      "owner_membership" => %{
        "user_id" => Map.fetch!(links, :owner_user_id),
        "role_id" => Map.fetch!(links, :owner_role_id),
        "role" => "Owner",
        "member_added_event_hash" => Map.fetch!(links, :owner_member_added_event_hash)
      },
      "workspace_member_envelope_commitment_hash" =>
        Map.fetch!(links, :workspace_member_envelope_commitment_hash)
    }
  end

  def compound_context_hash!(registration_id, prepare_request_hash, intent, links) do
    registration_id
    |> compound_context!(prepare_request_hash, intent, links)
    |> hash()
  end

  defp build_and_insert!(genesis, challenge, prepared, now) do
    compound_intent_id = Ecto.UUID.generate()
    mutation_id = Ecto.UUID.generate()
    issued_at = now |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
    expires_at = earliest_expiry(genesis.expires_at, challenge.expires_at)

    kd = build_key_directory_effects!(genesis, prepared, issued_at)
    key_directory_effects_hash = global_effects_hash(kd.user, kd.workspace)

    audit =
      build_audit_scopes!(
        genesis,
        prepared,
        mutation_id,
        key_directory_effects_hash,
        kd
      )

    base_intent = %{
      "protocol" => @protocol,
      "version" => @version,
      "compound_intent_id" => compound_intent_id,
      "mutation_id" => mutation_id,
      "challenge_id" => genesis.registration_id,
      "expires_at" => expires_at |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
      "key_directory_effects_hash" => key_directory_effects_hash,
      "scopes" => [audit.user, audit.workspace]
    }

    links = %{
      user_device_key_added_event_hash: kd.user.device_event_hash,
      workspace_device_key_added_event_hash: kd.workspace.device_event_hash,
      owner_user_id: genesis.reserved_user_id,
      owner_role_id: genesis.reserved_workspace_role_ids["owner"],
      owner_member_added_event_hash: kd.workspace.member_event_hash,
      workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash
    }

    genesis_context_hash =
      compound_context_hash!(
        genesis.registration_id,
        prepared.prepare_request_hash,
        base_intent,
        links
      )

    genesis_transcript =
      Signature.build_genesis_device_bootstrap_transcript!(%{
        registration_id: genesis.registration_id,
        compound_intent_id: compound_intent_id,
        mutation_id: mutation_id,
        genesis_compound_context_hash: genesis_context_hash,
        user_id: genesis.reserved_user_id,
        workspace_id: genesis.reserved_workspace_id,
        owner_role_id: genesis.reserved_workspace_role_ids["owner"],
        device_id: prepared.params["device_id"],
        device_public_material: prepared.params["device_hybrid_signing_public_key_material"],
        device_hybrid_encryption_public_key_material:
          prepared.params["device_hybrid_encryption_public_key_material"],
        client_nonce: prepared.params["client_nonce"],
        registration_challenge_hash: challenge.challenge_hash,
        identity_signing_key_id: prepared.identity_signing_key_id,
        user_identity_public_key_hash:
          hash(prepared.params["identity_hybrid_signing_public_key_material"]),
        user_device_key_added_event_hash: kd.user.device_event_hash,
        workspace_device_key_added_event_hash: kd.workspace.device_event_hash,
        owner_member_added_event_hash: kd.workspace.member_event_hash,
        workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash,
        user_audit_checkpoint: %{
          "sequence" => 2,
          "checkpoint_hash" => audit.user["checkpoint_payload_hash"]
        },
        workspace_audit_checkpoint: %{
          "sequence" => 1,
          "checkpoint_hash" => audit.workspace["checkpoint_payload_hash"]
        }
      })

    genesis_requirement =
      requirement(
        length(audit.workspace["effect_signature_requirements"]) + 1,
        "genesis_device_bootstrap",
        "genesis_device_bootstrap",
        "none",
        hash(genesis_transcript),
        prepared.identity_signing_key_id
      )

    intent =
      put_in(
        base_intent,
        ["scopes", Access.at(1), "effect_signature_requirements"],
        audit.workspace["effect_signature_requirements"] ++ [genesis_requirement]
      )

    prepare_bytes = JCS.canonical_bytes!(prepared.params)
    intent_bytes = JCS.canonical_bytes!(intent)

    %PendingGenesisIntent{}
    |> PendingGenesisIntent.changeset(%{
      registration_id: genesis.registration_id,
      compound_intent_id: compound_intent_id,
      mutation_id: mutation_id,
      prepare_request_jcs_b64u: Base.url_encode64(prepare_bytes, padding: false),
      prepare_request_hash: prepared.prepare_request_hash,
      compound_intent_jcs_b64u: Base.url_encode64(intent_bytes, padding: false),
      intent_hash: Hash.blake3_base64url(intent_bytes),
      expires_at: expires_at,
      created_at: now
    })
    |> Repo.insert!()

    intent
  end

  defp build_key_directory_effects!(genesis, prepared, issued_at) do
    p = prepared.params
    user_id = genesis.reserved_user_id
    workspace_id = genesis.reserved_workspace_id
    owner_role_id = genesis.reserved_workspace_role_ids["owner"]
    identity_actor = identity_actor(user_id, prepared.identity_signing_key_id)

    device_actor =
      genesis_device_actor(user_id, p["device_id"], prepared.device_signing_key_id, workspace_id)

    user_signing =
      event("user", user_id, 1, "identity_key_added", identity_actor, %{
        "key_kind" => "signing",
        "key_id" => prepared.identity_signing_key_id,
        "key_material_hash" => hash(p["identity_hybrid_signing_public_key_material"])
      })

    user_encryption =
      event(
        "user",
        user_id,
        2,
        "identity_key_added",
        identity_actor,
        %{
          "key_kind" => "encryption",
          "key_id" => prepared.identity_encryption_key_id,
          "key_material_hash" => hash(p["identity_hybrid_encryption_public_key_material"])
        },
        event_hash(user_signing)
      )

    user_suite =
      event(
        "user",
        user_id,
        3,
        "suite_policy_changed",
        identity_actor,
        p["initial_suite_policy"],
        event_hash(user_encryption)
      )

    user_device =
      event(
        "user",
        user_id,
        4,
        "device_key_added",
        identity_actor,
        device_body(prepared),
        event_hash(user_suite)
      )

    user_events = [user_signing, user_encryption, user_suite, user_device]
    user_checkpoint = checkpoint("user", user_id, issued_at, user_events, prepared)

    workspace_signing =
      event("workspace", workspace_id, 1, "identity_key_added", device_actor, %{
        "key_kind" => "signing",
        "key_id" => prepared.identity_signing_key_id,
        "key_material_hash" => hash(p["identity_hybrid_signing_public_key_material"])
      })

    workspace_encryption =
      event(
        "workspace",
        workspace_id,
        2,
        "identity_key_added",
        device_actor,
        %{
          "key_kind" => "encryption",
          "key_id" => prepared.identity_encryption_key_id,
          "key_material_hash" => hash(p["identity_hybrid_encryption_public_key_material"])
        },
        event_hash(workspace_signing)
      )

    workspace_device =
      event(
        "workspace",
        workspace_id,
        3,
        "device_key_added",
        device_actor,
        device_body(prepared),
        event_hash(workspace_encryption)
      )

    workspace_member =
      event(
        "workspace",
        workspace_id,
        4,
        "member_added",
        device_actor,
        %{
          "workspace_id" => workspace_id,
          "user_id" => user_id,
          "role_id" => owner_role_id,
          "base_role" => "owner",
          "workspace_member_envelope_hash" => prepared.member_envelope.commitment_hash
        },
        event_hash(workspace_device)
      )

    workspace_suite =
      event(
        "workspace",
        workspace_id,
        5,
        "suite_policy_changed",
        device_actor,
        p["initial_suite_policy"],
        event_hash(workspace_member)
      )

    workspace_envelope =
      event(
        "workspace",
        workspace_id,
        6,
        "workspace_member_envelope_issued",
        device_actor,
        member_envelope_body(prepared, event_hash(workspace_member)),
        event_hash(workspace_suite)
      )

    workspace_events = [
      workspace_signing,
      workspace_encryption,
      workspace_device,
      workspace_member,
      workspace_suite,
      workspace_envelope
    ]

    workspace_checkpoint =
      checkpoint("workspace", workspace_id, issued_at, workspace_events, prepared)

    %{
      user:
        effect_scope(
          user_events,
          user_checkpoint,
          prepared.identity_signing_key_id,
          "identity_initial",
          "identity"
        ),
      workspace:
        effect_scope(
          workspace_events,
          workspace_checkpoint,
          prepared.device_signing_key_id,
          "workspace_initial",
          "device"
        )
        |> Map.merge(%{
          device_event_hash: event_hash(workspace_device),
          member_event_hash: event_hash(workspace_member),
          envelope_event: workspace_envelope
        })
    }
    |> put_in([:user, :device_event_hash], event_hash(user_device))
    |> put_in(
      [:workspace, :pq_wrap_requirement],
      pq_wrap_requirement(prepared, workspace_envelope, workspace_checkpoint)
    )
  end

  defp build_audit_scopes!(genesis, prepared, mutation_id, effects_hash, kd) do
    account_command = %{
      "user_id" => genesis.reserved_user_id,
      "identity_signing_key_id" => prepared.identity_signing_key_id,
      "identity_encryption_key_id" => prepared.identity_encryption_key_id,
      "initial_device_id" => prepared.params["device_id"],
      "bootstrap_prepare_request_hash" => prepared.prepare_request_hash,
      "recovery_authorization_key_id" =>
        prepared.recovery_authorization["recovery_authorization_key_id"],
      "initial_suite_policy_hash" => hash(prepared.params["initial_suite_policy"])
    }

    workspace_command = %{
      "workspace_id" => genesis.reserved_workspace_id,
      "owner_user_id" => genesis.reserved_user_id,
      "owner_device_id" => prepared.params["device_id"],
      "owner_role_id" => genesis.reserved_workspace_role_ids["owner"],
      "workspace_member_envelope_hash" => prepared.member_envelope.commitment_hash,
      "initial_suite_policy_hash" => hash(prepared.params["initial_suite_policy"])
    }

    user_account =
      audit_event(%{
        scope_kind: "user",
        scope_id: genesis.reserved_user_id,
        sequence: 1,
        type: "user.account.genesis",
        mutation_id: mutation_id,
        subject_kind: "user_account",
        subject_id: genesis.reserved_user_id,
        actor: %{"kind" => "identity", "user_id" => genesis.reserved_user_id},
        request_hash: hash(account_command),
        effects_hash: effects_hash
      })

    user_device =
      audit_event(%{
        scope_kind: "user",
        scope_id: genesis.reserved_user_id,
        sequence: 2,
        type: "user.device.genesis_bootstrapped",
        mutation_id: mutation_id,
        subject_kind: "user_device",
        subject_id: prepared.params["device_id"],
        actor: %{"kind" => "identity", "user_id" => genesis.reserved_user_id},
        request_hash: prepared.prepare_request_hash,
        effects_hash: effects_hash,
        previous_event_hash: audit_event_hash(user_account)
      })

    workspace =
      audit_event(%{
        scope_kind: "workspace",
        scope_id: genesis.reserved_workspace_id,
        sequence: 1,
        type: "workspace.genesis",
        mutation_id: mutation_id,
        subject_kind: "workspace",
        subject_id: genesis.reserved_workspace_id,
        actor: %{
          "kind" => "device",
          "user_id" => genesis.reserved_user_id,
          "device_id" => prepared.params["device_id"]
        },
        request_hash: hash(workspace_command),
        effects_hash: effects_hash
      })

    user_checkpoint =
      audit_checkpoint(
        "user_identity",
        user_device,
        prepared.identity_signing_key_id,
        genesis.reserved_user_id,
        nil
      )

    workspace_checkpoint =
      audit_checkpoint(
        "workspace_device",
        workspace,
        prepared.device_signing_key_id,
        genesis.reserved_user_id,
        prepared.params["device_id"]
      )

    user_requirements = requirements(kd.user, prepared, "user")

    workspace_requirements =
      requirements(kd.workspace, prepared, "workspace") ++
        [kd.workspace.pq_wrap_requirement]

    %{
      user:
        intent_scope(
          "user",
          genesis.reserved_user_id,
          [user_account, user_device],
          kd.user,
          user_checkpoint,
          "user_identity",
          user_requirements
        ),
      workspace:
        intent_scope(
          "workspace",
          genesis.reserved_workspace_id,
          [workspace],
          kd.workspace,
          workspace_checkpoint,
          "workspace_device",
          workspace_requirements
        )
    }
  end

  defp effect_scope(events, checkpoint, signer_key_id, checkpoint_variant, owner_kind) do
    effects =
      events
      |> Enum.with_index(1)
      |> Enum.map(fn {payload, order} ->
        %{
          "effect_order" => order,
          "event_payload" => payload,
          "event_hash" => event_hash(payload)
        }
      end)

    %{
      events: events,
      checkpoint: checkpoint,
      effects: effects,
      checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint),
      signer_key_id: signer_key_id,
      checkpoint_variant: checkpoint_variant,
      owner_kind: owner_kind
    }
  end

  defp requirements(scope, prepared, scope_kind) do
    {owner_kind, owner_id, signer_key_id, signer} =
      case scope_kind do
        "user" ->
          {"identity", prepared.params["user_id"], prepared.identity_signing_key_id,
           checkpoint_signer("identity", prepared)}

        "workspace" ->
          {"device", prepared.params["device_id"], prepared.device_signing_key_id,
           checkpoint_signer("device", prepared)}
      end

    event_requirements =
      scope.effects
      |> Enum.map(fn effect ->
        payload = effect["event_payload"]

        transcript =
          Signature.build_key_directory_event_transcript!(
            payload["event_type"],
            owner_kind,
            owner_id,
            payload
          )

        requirement(
          effect["effect_order"],
          "key_directory_event",
          "key_directory_event",
          payload["event_type"],
          hash(transcript),
          signer_key_id
        )
      end)

    checkpoint_transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        scope.checkpoint_variant,
        owner_kind,
        owner_id,
        scope.checkpoint,
        signer
      )

    event_requirements ++
      [
        requirement(
          length(event_requirements) + 1,
          "key_directory_checkpoint",
          "key_directory_checkpoint",
          scope.checkpoint_variant,
          hash(checkpoint_transcript),
          signer_key_id
        )
      ]
  end

  defp checkpoint_signer("identity", prepared),
    do: %{
      "signer_kind" => "identity",
      "user_id" => prepared.params["user_id"],
      "signing_key_id" => prepared.identity_signing_key_id,
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

  defp checkpoint_signer("device", prepared),
    do: %{
      "signer_kind" => "device",
      "user_id" => prepared.params["user_id"],
      "device_id" => prepared.params["device_id"],
      "signing_key_id" => prepared.device_signing_key_id,
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

  defp pq_wrap_requirement(prepared, event, checkpoint) do
    m = prepared.member_envelope
    checkpoint_hash = KeyDirectory.checkpoint_hash(checkpoint)
    event_hash = event_hash(event)

    transcript =
      Signature.build_pq_wrap_transcript!(
        prepared.params["device_id"],
        prepared.params["workspace_member_envelope_precommit"]["wrap"]["sender"],
        %{
          "scope_kind" => "workspace",
          "scope_id" => prepared.params["workspace_id"],
          "event_hash" => event_hash,
          "operation_checkpoint_sequence" => 1,
          "operation_checkpoint_hash" => checkpoint_hash,
          "covered_event_head_sequence" => event["sequence"],
          "covered_event_head_hash" => event_hash
        },
        %{
          "resource_hash" => m.resource_hash,
          "wrap_body_hash" => m.wrap_body_hash,
          "wrap_event_body_hash" => hash(event["body"]),
          "wrap_event_hash" => event_hash,
          "hpke_info_hash" => m.hpke_info_hash,
          "aad_hash" => m.aad_hash
        },
        "workspace_genesis"
      )

    requirement(8, "pq_wrap", "pq_wrap", "none", hash(transcript), prepared.device_signing_key_id)
  end

  defp intent_scope(kind, id, audit_events, kd, audit_checkpoint, variant, requirements) do
    head = List.last(audit_events)

    %{
      "chain_scope_kind" => kind,
      "chain_scope_id" => id,
      "current_event_head" => %{"sequence" => 0, "event_hash" => "GENESIS"},
      "previous_signed_checkpoint" => "GENESIS",
      "candidate_events" => audit_events,
      "candidate_event_head" => %{
        "sequence" => head["sequence"],
        "event_hash" => audit_event_hash(head)
      },
      "candidate_key_directory_effects" => kd.effects,
      "candidate_key_directory_checkpoint_payload" => kd.checkpoint,
      "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash,
      "scope_key_directory_effects_hash" => scope_effects_hash(kd),
      "effect_signature_requirements" => requirements,
      "checkpoint_payload_hash" => audit_checkpoint.checkpoint_hash,
      "required_checkpoint_variant" => variant
    }
  end

  defp audit_checkpoint(variant, event, signing_key_id, user_id, device_id) do
    payload =
      %{
        "protocol" => "refmd.signed-audit-checkpoint",
        "version" => 1,
        "chain_scope_kind" => event["chain_scope_kind"],
        "chain_scope_id" => event["chain_scope_id"],
        "sequence" => event["sequence"],
        "event_hash" => audit_event_hash(event),
        "signer_user_id" => user_id,
        "signing_key_id" => signing_key_id,
        "authorization_checkpoint_scope_kind" => event["chain_scope_kind"],
        "authorization_checkpoint_scope_id" => event["chain_scope_id"],
        "authorization_checkpoint_sequence" => 0,
        "authorization_checkpoint_hash" => "GENESIS",
        "covered_event_class" => "authority",
        "covered_event_type" => event["event_type"]
      }
      |> maybe_put("signer_device_id", device_id)

    %{payload: payload, checkpoint_hash: Audit.checkpoint_hash!(variant, payload)}
  end

  defp audit_event(attrs) do
    event = %{
      "protocol" => "refmd.audit.chain-event",
      "version" => 1,
      "event_id" => Ecto.UUID.generate(),
      "chain_scope_kind" => attrs.scope_kind,
      "chain_scope_id" => attrs.scope_id,
      "sequence" => attrs.sequence,
      "previous_event_hash" => Map.get(attrs, :previous_event_hash, "GENESIS"),
      "event_type" => attrs.type,
      "event_body" => %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "mutation_id" => attrs.mutation_id,
        "event_type" => attrs.type,
        "chain_scope_kind" => attrs.scope_kind,
        "chain_scope_id" => attrs.scope_id,
        "subject_kind" => attrs.subject_kind,
        "subject_id" => attrs.subject_id,
        "actor" => attrs.actor,
        "canonical_request_hash" => attrs.request_hash,
        "key_directory_effects_hash" => attrs.effects_hash
      }
    }

    AuditChainEvent.assert_valid!(event)
    Map.put(event, "event_hash", AuditChainEvent.hash!(event))
  end

  defp event(scope_kind, scope_id, sequence, type, actor, body, previous \\ nil) do
    %{
      "protocol" => "refmd.key-directory-event",
      "version" => 1,
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "sequence" => sequence,
      "event_type" => type,
      "actor" => actor,
      "body" => body
    }
    |> maybe_put("previous_event_hash", previous)
  end

  defp checkpoint(scope_kind, scope_id, issued_at, events, prepared) do
    [identity_signing, identity_encryption | _] = events
    device = Enum.find(events, &(&1["event_type"] == "device_key_added"))
    policy = Suite.current_suite_policy()

    %{
      "protocol" => "refmd.key-directory-checkpoint",
      "version" => 1,
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "sequence" => 1,
      "issued_at" => issued_at,
      "suite_policy_version" => policy["suite_policy_version"],
      "min_suite_rank" => policy["min_suite_rank"],
      "allowed_suite_ids" => policy["allowed_suite_ids"],
      "required_components" => policy["required_components"],
      "identity_keys" => [
        Payload.key_entry!(
          prepared.params["identity_hybrid_signing_public_key_material"],
          event_ref(identity_signing)
        ),
        Payload.key_entry!(
          prepared.params["identity_hybrid_encryption_public_key_material"],
          event_ref(identity_encryption)
        )
      ],
      "device_keys" => [
        Payload.key_entry!(
          prepared.params["device_hybrid_signing_public_key_material"],
          event_ref(device)
        ),
        Payload.key_entry!(
          prepared.params["device_hybrid_encryption_public_key_material"],
          event_ref(device)
        )
      ],
      "share_participant_keys" => [],
      "revoked_key_ids" => [],
      "covered_event_head" => %{
        "head_sequence" => List.last(events)["sequence"],
        "head_hash" => event_hash(List.last(events))
      }
    }
  end

  defp member_envelope_body(prepared, authorization_event_hash) do
    p = prepared.params
    m = prepared.member_envelope

    %{
      "workspace_id" => p["workspace_id"],
      "target_user_id" => p["user_id"],
      "kek_version" => 1,
      "suite_id" => p["workspace_member_envelope_precommit"]["wrap"]["suite_id"],
      "sender_user_id" => p["user_id"],
      "sender_device_id" => p["device_id"],
      "sender_key_checkpoint_sequence" => 0,
      "sender_key_checkpoint_hash" => "GENESIS",
      "target_identity_encryption_key_id" => prepared.identity_encryption_key_id,
      "target_identity_key_material_hash" =>
        hash(p["identity_hybrid_encryption_public_key_material"]),
      "authorization_key_directory_checkpoint_sequence" => 1,
      "authorization_key_directory_checkpoint_hash" => "GENESIS",
      "authorization_event_hash" => authorization_event_hash,
      "wrap_protocol" => "refmd.signed-pq-hybrid-wrap",
      "wrap_version" => 1,
      "wrap_purpose" => "workspace_member_kek_wrap",
      "wrap_resource_hash" => m.resource_hash,
      "wrap_body_hash" => m.wrap_body_hash,
      "ciphertext_hash" => m.ciphertext_hash,
      "workspace_member_envelope_hash" => m.commitment_hash
    }
  end

  defp device_body(prepared),
    do: %{
      "user_id" => prepared.params["user_id"],
      "device_id" => prepared.params["device_id"],
      "signing_key_id" => prepared.device_signing_key_id,
      "encryption_key_id" => prepared.device_encryption_key_id
    }

  defp identity_actor(user_id, signing_key_id),
    do: %{
      "signer_kind" => "identity",
      "user_id" => user_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "user",
      "key_scope_id" => user_id,
      "key_checkpoint_sequence" => 0,
      "key_checkpoint_hash" => "GENESIS"
    }

  defp genesis_device_actor(user_id, device_id, signing_key_id, workspace_id),
    do: %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => 0,
      "key_checkpoint_hash" => "GENESIS"
    }

  defp requirement(order, kind, purpose, variant, subject_hash, signer_key_id),
    do: %{
      "requirement_order" => order,
      "authorization_kind" => kind,
      "signing_purpose" => purpose,
      "surface_variant" => variant,
      "subject_hash" => subject_hash,
      "signer_key_id" => signer_key_id
    }

  defp global_effects_hash(user, workspace),
    do:
      hash(%{
        "scopes" => [effect_hash_scope("user", user), effect_hash_scope("workspace", workspace)]
      })

  defp effect_hash_scope(kind, scope),
    do: %{
      "chain_scope_kind" => kind,
      "chain_scope_id" => scope.checkpoint["scope_id"],
      "events" => scope.events,
      "checkpoint" => scope.checkpoint
    }

  defp scope_effects_hash(scope),
    do:
      hash(%{
        "candidate_key_directory_effects" => scope.effects,
        "candidate_key_directory_checkpoint_payload" => scope.checkpoint,
        "candidate_key_directory_checkpoint_hash" => scope.checkpoint_hash
      })

  defp compound_context_scope!(scope),
    do: %{
      "chain_scope_kind" => scope["chain_scope_kind"],
      "chain_scope_id" => scope["chain_scope_id"],
      "candidate_event_head_sequence" => scope["candidate_event_head"]["sequence"],
      "candidate_event_head_hash" => scope["candidate_event_head"]["event_hash"],
      "candidate_key_directory_checkpoint_hash" =>
        scope["candidate_key_directory_checkpoint_hash"],
      "checkpoint_payload_hash" => scope["checkpoint_payload_hash"]
    }

  defp event_ref(event),
    do: %{
      "scope_kind" => event["scope_kind"],
      "scope_id" => event["scope_id"],
      "event_sequence" => event["sequence"],
      "event_hash" => event_hash(event)
    }

  defp event_hash(%{"event_hash" => hash}), do: hash
  defp event_hash(event), do: KeyDirectory.event_hash(event)
  defp audit_event_hash(%{"event_hash" => hash}), do: hash
  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp lock_challenge!(genesis, session, params, now) do
    challenge_hash =
      params["registration_challenge"]
      |> Base.url_decode64!(padding: false)
      |> Hash.blake3_base64url()

    challenge =
      from(c in PendingGenesisChallenge,
        where: c.registration_id == ^genesis.registration_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one!()

    unless challenge.pending_genesis_session_token_hash == session.token_hash and
             challenge.challenge_hash == challenge_hash and is_nil(challenge.consumed_at) and
             DateTime.compare(challenge.expires_at, now) == :gt,
           do: Repo.rollback(:invalid_genesis_challenge)

    challenge
  end

  defp lock_existing(registration_id) do
    from(i in PendingGenesisIntent,
      where: i.registration_id == ^registration_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp return_existing!(existing, prepare_hash, now) do
    unless existing.prepare_request_hash == prepare_hash and
             DateTime.compare(existing.expires_at, now) == :gt,
           do: Repo.rollback(:genesis_intent_reuse)

    existing.compound_intent_jcs_b64u
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end

  defp earliest_expiry(left, right) do
    if DateTime.compare(left, right) == :gt, do: right, else: left
  end
end
