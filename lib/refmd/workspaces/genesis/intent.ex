defmodule RefMD.Workspaces.Genesis.Intent do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Payload
  alias RefMD.Security.{AuditChainEvent, CompoundAppend}
  alias RefMD.Workspaces.Genesis.Prepare

  def issue!(user_id, device_id, command) do
    prepared = Prepare.validate!(user_id, device_id, command)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    issued_at = DateTime.to_iso8601(now)
    expires_at = now |> DateTime.add(300, :second) |> DateTime.to_iso8601()
    mutation_id = Ecto.UUID.generate()

    kd = build_key_directory!(prepared, issued_at)
    effects_hash = global_effects_hash(kd)
    audit = build_audit!(prepared, mutation_id, effects_hash)
    requirements = build_requirements!(prepared, kd)

    scope = %{
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => prepared.workspace_id,
      "current_event_head" => %{"sequence" => 0, "event_hash" => "GENESIS"},
      "previous_signed_checkpoint" => "GENESIS",
      "candidate_events" => [audit.event],
      "candidate_event_head" => %{
        "sequence" => audit.event["sequence"],
        "event_hash" => audit.event["event_hash"]
      },
      "candidate_key_directory_effects" => kd.effects,
      "candidate_key_directory_checkpoint_payload" => kd.checkpoint,
      "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash,
      "scope_key_directory_effects_hash" =>
        hash(%{
          "candidate_key_directory_effects" => kd.effects,
          "candidate_key_directory_checkpoint_payload" => kd.checkpoint,
          "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash
        }),
      "effect_signature_requirements" => requirements,
      "checkpoint_payload_hash" => audit.checkpoint_hash,
      "required_checkpoint_variant" => "workspace_device"
    }

    intent = %{
      "protocol" => "refmd.audit.compound-append-intent",
      "version" => 1,
      "compound_intent_id" => Ecto.UUID.generate(),
      "mutation_id" => mutation_id,
      "challenge_id" => Ecto.UUID.generate(),
      "expires_at" => expires_at,
      "key_directory_effects_hash" => effects_hash,
      "scopes" => [scope]
    }

    CompoundAppend.persist_intent!(intent, command, %{
      mutation_kind: "workspace_genesis",
      actor_user_id: user_id,
      actor_device_id: device_id,
      created_at: now
    })
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  else
    intent -> {:ok, intent}
  end

  defp build_key_directory!(p, issued_at) do
    actor = device_actor(p)

    signing =
      event(p, 1, "identity_key_added", actor, %{
        "key_kind" => "signing",
        "key_id" => p.identity_signing_key_id,
        "key_material_hash" => hash(p.identity_signing_material)
      })

    encryption =
      event(
        p,
        2,
        "identity_key_added",
        actor,
        %{
          "key_kind" => "encryption",
          "key_id" => p.identity_encryption_key_id,
          "key_material_hash" => hash(p.identity_encryption_material)
        },
        event_hash(signing)
      )

    device =
      event(
        p,
        3,
        "device_key_added",
        actor,
        %{
          "user_id" => p.user_id,
          "device_id" => p.device_id,
          "signing_key_id" => p.device_signing_key_id,
          "encryption_key_id" => p.device_encryption_key_id
        },
        event_hash(encryption)
      )

    member =
      event(
        p,
        4,
        "member_added",
        actor,
        %{
          "workspace_id" => p.workspace_id,
          "user_id" => p.user_id,
          "role_id" => p.owner_role_id,
          "base_role" => "owner",
          "workspace_member_envelope_hash" => p.member_envelope.commitment_hash
        },
        event_hash(device)
      )

    suite =
      event(p, 5, "suite_policy_changed", actor, p.suite_policy, event_hash(member))

    envelope =
      event(
        p,
        6,
        "workspace_member_envelope_issued",
        actor,
        member_envelope_body(p, event_hash(member)),
        event_hash(suite)
      )

    events = [signing, encryption, device, member, suite, envelope]
    checkpoint = checkpoint(p, issued_at, events)

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
      effects: effects,
      checkpoint: checkpoint,
      checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint),
      envelope_event: envelope
    }
  end

  defp build_audit!(p, mutation_id, effects_hash) do
    command = %{
      "workspace_id" => p.workspace_id,
      "owner_user_id" => p.user_id,
      "owner_device_id" => p.device_id,
      "owner_role_id" => p.owner_role_id,
      "workspace_member_envelope_hash" => p.member_envelope.commitment_hash,
      "initial_suite_policy_hash" => hash(p.suite_policy)
    }

    event =
      AuditChainEvent.build!(%{
        "event_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "workspace",
        "chain_scope_id" => p.workspace_id,
        "sequence" => 1,
        "previous_event_hash" => "GENESIS",
        "event_type" => "workspace.genesis",
        "event_body" => %{
          "protocol" => "refmd.audit.high-risk-mutation",
          "version" => 1,
          "event_type" => "workspace.genesis",
          "chain_scope_kind" => "workspace",
          "chain_scope_id" => p.workspace_id,
          "mutation_id" => mutation_id,
          "subject_kind" => "workspace",
          "subject_id" => p.workspace_id,
          "actor" => %{"kind" => "device", "user_id" => p.user_id, "device_id" => p.device_id},
          "canonical_request_hash" => hash(command),
          "key_directory_effects_hash" => effects_hash
        }
      })
      |> then(&AuditChainEvent.envelope!(&1, AuditChainEvent.hash!(&1)))

    payload = audit_checkpoint_payload(p, event)
    %{event: event, checkpoint_hash: Audit.checkpoint_hash!("workspace_device", payload)}
  end

  defp build_requirements!(p, kd) do
    event_requirements =
      Enum.map(kd.effects, fn effect ->
        payload = effect["event_payload"]

        transcript =
          Signature.build_key_directory_event_transcript!(
            payload["event_type"],
            "device",
            p.device_id,
            payload
          )

        requirement(
          effect["effect_order"],
          "key_directory_event",
          "key_directory_event",
          payload["event_type"],
          hash(transcript),
          p.device_signing_key_id
        )
      end)

    signer = %{
      "signer_kind" => "device",
      "user_id" => p.user_id,
      "device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

    checkpoint_transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        "workspace_initial",
        "device",
        p.device_id,
        kd.checkpoint,
        signer
      )

    checkpoint_requirement =
      requirement(
        7,
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "workspace_initial",
        hash(checkpoint_transcript),
        p.device_signing_key_id
      )

    wrap_transcript = pq_wrap_transcript(p, kd)

    event_requirements ++
      [
        checkpoint_requirement,
        requirement(
          8,
          "pq_wrap",
          "pq_wrap",
          "none",
          hash(wrap_transcript),
          p.device_signing_key_id
        )
      ]
  end

  defp checkpoint(p, issued_at, events) do
    [signing, encryption, device | _] = events
    policy = p.suite_policy

    %{
      "protocol" => "refmd.key-directory-checkpoint",
      "version" => 1,
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "sequence" => 1,
      "issued_at" => issued_at,
      "suite_policy_version" => policy["suite_policy_version"],
      "min_suite_rank" => policy["min_suite_rank"],
      "allowed_suite_ids" => policy["allowed_suite_ids"],
      "required_components" => policy["required_components"],
      "identity_keys" => [
        Payload.key_entry!(p.identity_signing_material, event_ref(signing)),
        Payload.key_entry!(p.identity_encryption_material, event_ref(encryption))
      ],
      "device_keys" => [
        Payload.key_entry!(p.device_signing_material, event_ref(device)),
        Payload.key_entry!(p.device_encryption_material, event_ref(device))
      ],
      "share_participant_keys" => [],
      "revoked_key_ids" => [],
      "covered_event_head" => %{
        "head_sequence" => List.last(events)["sequence"],
        "head_hash" => event_hash(List.last(events))
      }
    }
  end

  defp audit_checkpoint_payload(p, event) do
    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => p.workspace_id,
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => p.user_id,
      "signer_device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "authorization_checkpoint_scope_kind" => "workspace",
      "authorization_checkpoint_scope_id" => p.workspace_id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => "workspace.genesis"
    }
  end

  defp pq_wrap_transcript(p, kd) do
    event = kd.envelope_event
    event_hash = event_hash(event)
    member = p.member_envelope
    sender = p.command["workspace_member_envelope_precommit"]["wrap"]["sender"]

    Signature.build_pq_wrap_transcript!(
      p.device_id,
      sender,
      %{
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "event_hash" => event_hash,
        "operation_checkpoint_sequence" => 1,
        "operation_checkpoint_hash" => kd.checkpoint_hash,
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
  end

  defp member_envelope_body(p, authorization_event_hash) do
    m = p.member_envelope
    wrap = p.command["workspace_member_envelope_precommit"]["wrap"]

    %{
      "workspace_id" => p.workspace_id,
      "target_user_id" => p.user_id,
      "kek_version" => 1,
      "suite_id" => wrap["suite_id"],
      "sender_user_id" => p.user_id,
      "sender_device_id" => p.device_id,
      "sender_key_checkpoint_sequence" => 0,
      "sender_key_checkpoint_hash" => "GENESIS",
      "target_identity_encryption_key_id" => p.identity_encryption_key_id,
      "target_identity_key_material_hash" => hash(p.identity_encryption_material),
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

  defp event(p, sequence, type, actor, body, previous \\ nil) do
    %{
      "protocol" => "refmd.key-directory-event",
      "version" => 1,
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "sequence" => sequence,
      "event_type" => type,
      "actor" => actor,
      "body" => body
    }
    |> maybe_put("previous_event_hash", previous)
  end

  defp device_actor(p),
    do: %{
      "signer_kind" => "device",
      "user_id" => p.user_id,
      "device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => p.workspace_id,
      "key_checkpoint_sequence" => 0,
      "key_checkpoint_hash" => "GENESIS"
    }

  defp event_ref(event),
    do: %{
      "scope_kind" => event["scope_kind"],
      "scope_id" => event["scope_id"],
      "event_sequence" => event["sequence"],
      "event_hash" => event_hash(event)
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

  defp global_effects_hash(kd),
    do:
      hash(%{
        "scopes" => [
          %{
            "chain_scope_kind" => "workspace",
            "chain_scope_id" => kd.checkpoint["scope_id"],
            "events" => kd.events,
            "checkpoint" => kd.checkpoint
          }
        ]
      })

  defp event_hash(event), do: KeyDirectory.event_hash(event)
  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
  defp error_message(%Ecto.InvalidChangesetError{} = error), do: error.changeset
  defp error_message(%ArgumentError{} = error), do: error.message
end
