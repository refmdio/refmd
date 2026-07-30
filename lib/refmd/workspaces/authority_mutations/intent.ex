defmodule RefMD.Workspaces.AuthorityMutations.Intent do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Security.{AuditChainEvent, CompoundAppend}
  alias RefMD.Workspaces.AuthorityMutations.Prepare
  alias RefMD.Workspaces.KekRotation.Directory

  def issue(actor_user_id, actor_device_id, event_type, command, candidate) do
    prepared = Prepare.validate!(actor_user_id, actor_device_id, event_type, command)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    mutation_id = Ecto.UUID.generate()
    kd = candidate_key_directory!(prepared, candidate)
    effects_hash = global_effects_hash(prepared.workspace_id, kd)
    audit = audit_event(prepared, mutation_id, effects_hash, kd)
    audit_payload = audit_checkpoint_payload(prepared, audit)
    requirements = requirements(prepared, kd)

    scope = %{
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => prepared.workspace_id,
      "current_event_head" => string_keys(prepared.audit_head),
      "previous_signed_checkpoint" => %{
        "sequence" => prepared.previous_signed_audit_checkpoint["payload"]["sequence"],
        "checkpoint_hash" => prepared.previous_signed_audit_checkpoint["checkpoint_hash"]
      },
      "candidate_events" => [audit],
      "candidate_event_head" => %{
        "sequence" => audit["sequence"],
        "event_hash" => audit["event_hash"]
      },
      "candidate_key_directory_effects" => kd.effects,
      "candidate_key_directory_checkpoint_payload" => kd.checkpoint_payload,
      "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash,
      "scope_key_directory_effects_hash" =>
        hash(%{
          "candidate_key_directory_effects" => kd.effects,
          "candidate_key_directory_checkpoint_payload" => kd.checkpoint_payload,
          "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash
        }),
      "effect_signature_requirements" => requirements,
      "checkpoint_payload_hash" => Audit.checkpoint_hash!("workspace_device", audit_payload),
      "required_checkpoint_variant" => "workspace_device"
    }

    intent = %{
      "protocol" => "refmd.audit.compound-append-intent",
      "version" => 1,
      "compound_intent_id" => Ecto.UUID.generate(),
      "mutation_id" => mutation_id,
      "challenge_id" => Ecto.UUID.generate(),
      "expires_at" => now |> DateTime.add(300, :second) |> DateTime.to_iso8601(),
      "key_directory_effects_hash" => effects_hash,
      "scopes" => [scope]
    }

    {:ok,
     CompoundAppend.persist_intent!(intent, command, %{
       mutation_kind: event_type,
       actor_user_id: actor_user_id,
       actor_device_id: actor_device_id,
       created_at: now
     })}
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  end

  def audit_checkpoint_payload(p, event) do
    previous = p.previous_signed_audit_checkpoint

    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => p.workspace_id,
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "previous_signed_checkpoint_sequence" => previous["payload"]["sequence"],
      "previous_signed_checkpoint_hash" => previous["checkpoint_hash"],
      "signer_user_id" => p.actor_user_id,
      "signer_device_id" => p.actor_device_id,
      "signing_key_id" => p.actor_signing_key_id,
      "authorization_checkpoint_scope_kind" => "workspace",
      "authorization_checkpoint_scope_id" => p.workspace_id,
      "authorization_checkpoint_sequence" => p.key_checkpoint.sequence,
      "authorization_checkpoint_hash" => p.key_checkpoint.checkpoint_hash,
      "covered_event_class" => "authority",
      "covered_event_type" => event["event_type"]
    }
  end

  def checkpoint_signer(p) do
    %{
      "signer_kind" => "device",
      "user_id" => p.actor_user_id,
      "device_id" => p.actor_device_id,
      "signing_key_id" => p.actor_signing_key_id,
      "authorizing_checkpoint_sequence" => p.key_checkpoint.sequence,
      "authorizing_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
    }
  end

  defp candidate_key_directory!(%{event_type: "workspace.kek.rotation_completed"} = p, _) do
    current = p.key_checkpoint.payload
    covered = current["covered_event_head"]
    actor = completion_actor(p)
    first_sequence = covered["head_sequence"] + 1

    manifest_hash =
      Directory.completion_manifest_hash(p.business.workspace, p.command, p.business)

    completed =
      key_event(p, first_sequence, "rotation_completed", actor, covered["head_hash"], %{
        "event_type" => "rotation_completed",
        "rotation_kind" => "kek",
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "old_key_version" => p.command["old_key_version"],
        "new_key_version" => p.command["new_key_version"],
        "completed_at_event_sequence" => first_sequence,
        "completion_manifest_hash" => manifest_hash
      })

    {device_events, previous_hash, next_sequence} =
      build_device_wrap_events(p, actor, completed, first_sequence + 1)

    {member_events, previous_hash, next_sequence} =
      build_member_envelope_events(p, actor, previous_hash, next_sequence, completed)

    {workspace_invitation_events, previous_hash, next_sequence} =
      build_invitation_update_events(
        p,
        actor,
        previous_hash,
        next_sequence,
        "workspace_invitation_bootstrap_updated",
        p.command["workspace_invitation_updates"]
      )

    {guest_invitation_events, _previous_hash, _next_sequence} =
      build_invitation_update_events(
        p,
        actor,
        previous_hash,
        next_sequence,
        "guest_invitation_bootstrap_updated",
        p.command["guest_invitation_updates"]
      )

    events =
      [completed] ++
        device_events ++ member_events ++ workspace_invitation_events ++ guest_invitation_events

    candidate_from_payloads!(p, events, current)
  end

  defp candidate_key_directory!(%{event_type: "workspace.kek.old_key_deleted"} = p, _) do
    current = p.key_checkpoint.payload
    covered = current["covered_event_head"]
    sequence = covered["head_sequence"] + 1

    event =
      key_event(p, sequence, "old_key_deleted", completion_actor(p), covered["head_hash"], %{
        "event_type" => "old_key_deleted",
        "rotation_kind" => "kek",
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "old_key_version" => p.command["old_key_version"],
        "deleted_at_event_sequence" => sequence,
        "deletion_manifest_hash" => hash(p.command["deletion_manifest"])
      })

    candidate_from_payloads!(p, [event], current)
  end

  defp candidate_key_directory!(%{event_type: "workspace.member.role_changed"} = p, _) do
    current = p.key_checkpoint.payload
    covered = current["covered_event_head"]
    sequence = covered["head_sequence"] + 1

    event =
      key_event(p, sequence, "member_role_changed", completion_actor(p), covered["head_hash"], %{
        "workspace_id" => p.workspace_id,
        "user_id" => p.command["target_user_id"],
        "previous_role_id" => p.business.target_role.id,
        "previous_base_role" => p.business.target_role.base_role,
        "new_role_id" => p.business.new_role.id,
        "new_base_role" => p.business.new_role.base_role,
        "changed_at_event_sequence" => sequence
      })

    candidate_from_payloads!(p, [event], current)
  end

  defp candidate_key_directory!(%{event_type: "workspace.member.removed"} = p, _) do
    current = p.key_checkpoint.payload
    covered = current["covered_event_head"]
    actor = completion_actor(p)
    sequence = covered["head_sequence"] + 1

    removed =
      key_event(p, sequence, "member_removed", actor, covered["head_hash"], %{
        "workspace_id" => p.workspace_id,
        "user_id" => p.command["target_user_id"],
        "removed_at_event_sequence" => sequence
      })

    {revocations, previous_hash, sequence} =
      build_removal_invitation_events(p, actor, KeyDirectory.event_hash(removed), sequence + 1)

    {rotations, _previous_hash, _sequence} =
      build_removal_rotation_events(p, actor, previous_hash, sequence)

    candidate_from_payloads!(p, [removed] ++ revocations ++ rotations, current)
  end

  defp candidate_key_directory!(p, %{"events" => events, "checkpoint" => checkpoint})
       when is_list(events) and events != [] and is_map(checkpoint) do
    payloads = Enum.map(events, &Map.fetch!(&1, "payload"))
    checkpoint_payload = Map.fetch!(checkpoint, "payload")
    validate_recipe!(p, payloads)

    effects =
      payloads
      |> Enum.with_index(1)
      |> Enum.map(fn {payload, order} ->
        %{
          "effect_order" => order,
          "event_payload" => payload,
          "event_hash" => KeyDirectory.event_hash(payload)
        }
      end)

    %{
      effects: effects,
      checkpoint_payload: checkpoint_payload,
      checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint_payload)
    }
  rescue
    _ -> reraise ArgumentError, "workspace_authority_mutation_candidate_invalid", __STACKTRACE__
  end

  defp candidate_key_directory!(_, _),
    do: raise(ArgumentError, "workspace_authority_mutation_candidate_invalid")

  defp candidate_from_payloads!(p, payloads, current) do
    validate_recipe!(p, payloads)
    last = List.last(payloads)

    checkpoint_payload =
      KeyDirectory.build_checkpoint_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "sequence" => current["sequence"] + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => p.key_checkpoint.checkpoint_hash,
        "covered_event_head" => %{
          "head_sequence" => last["sequence"],
          "head_hash" => KeyDirectory.event_hash(last)
        },
        "identity_keys" => current["identity_keys"],
        "device_keys" => current["device_keys"],
        "share_participant_keys" => current["share_participant_keys"],
        "revoked_key_ids" => current["revoked_key_ids"]
      })

    effects =
      payloads
      |> Enum.with_index(1)
      |> Enum.map(fn {payload, order} ->
        %{
          "effect_order" => order,
          "event_payload" => payload,
          "event_hash" => KeyDirectory.event_hash(payload)
        }
      end)

    %{
      effects: effects,
      checkpoint_payload: checkpoint_payload,
      checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint_payload)
    }
  end

  defp build_removal_invitation_events(p, actor, previous_hash, sequence) do
    specs =
      Enum.map(p.business.workspace_invitations, fn invitation ->
        {"workspace_invitation_revoked", "invitation_id", invitation.id}
      end) ++
        Enum.map(p.business.guest_invitations, fn invitation ->
          {"guest_invitation_revoked", "guest_invitation_id", invitation.id}
        end)

    Enum.reduce(specs, {[], previous_hash, sequence}, fn {event_type, id_key, id},
                                                         {events, previous, seq} ->
      event =
        key_event(p, seq, event_type, actor, previous, %{
          "workspace_id" => p.workspace_id,
          id_key => id,
          "revoked_at_event_sequence" => seq,
          "reason" => "member_removed"
        })

      {events ++ [event], KeyDirectory.event_hash(event), seq + 1}
    end)
  end

  defp build_removal_rotation_events(p, actor, previous_hash, sequence) do
    specs =
      [
        %{
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => p.workspace_id,
          "old_key_version" => p.business.workspace.current_kek_version
        }
      ] ++
        Enum.map(p.business.documents, fn document ->
          %{
            "rotation_kind" => "dek",
            "scope_kind" => "document",
            "scope_id" => document.id,
            "old_key_version" => document.min_dek_version
          }
        end)

    Enum.reduce(specs, {[], previous_hash, sequence}, fn spec, {events, previous, seq} ->
      event =
        key_event(
          p,
          seq,
          "rotation_started",
          actor,
          previous,
          spec
          |> Map.put("event_type", "rotation_started")
          |> Map.put("new_key_version", spec["old_key_version"] + 1)
          |> Map.put("not_before_event_sequence", seq)
          |> Map.put("reason", "membership_change")
        )

      {events ++ [event], KeyDirectory.event_hash(event), seq + 1}
    end)
  end

  defp build_device_wrap_events(p, actor, previous, sequence) do
    Enum.reduce(
      p.business.device_wraps,
      {[], KeyDirectory.event_hash(previous), sequence},
      fn wrap, {events, previous_hash, seq} ->
        body = wrap_event_body(wrap)
        event = key_event(p, seq, "wrap_issued", actor, previous_hash, body)
        {events ++ [event], KeyDirectory.event_hash(event), seq + 1}
      end
    )
  end

  defp build_member_envelope_events(p, actor, previous_hash, sequence, completed) do
    authorization_event_hash = KeyDirectory.event_hash(completed)

    Enum.reduce(p.business.member_envelopes, {[], previous_hash, sequence}, fn envelope,
                                                                               {events, prev, seq} ->
      precommit = envelope.precommit
      wrap = precommit["wrap"]

      body = %{
        "workspace_id" => p.workspace_id,
        "target_user_id" => precommit["target_user_id"],
        "kek_version" => precommit["kek_version"],
        "suite_id" => wrap["suite_id"],
        "sender_user_id" => p.actor_user_id,
        "sender_device_id" => p.actor_device_id,
        "sender_key_checkpoint_sequence" => wrap["sender"]["key_checkpoint_sequence"],
        "sender_key_checkpoint_hash" => wrap["sender"]["key_checkpoint_hash"],
        "target_identity_encryption_key_id" => precommit["target_identity_encryption_key_id"],
        "target_identity_key_material_hash" => precommit["target_identity_key_material_hash"],
        "authorization_key_directory_checkpoint_sequence" =>
          precommit["authorization_key_directory_checkpoint_sequence"],
        "authorization_key_directory_checkpoint_hash" =>
          precommit["authorization_key_directory_checkpoint_hash"],
        "authorization_event_hash" => authorization_event_hash,
        "workspace_member_envelope_hash" => envelope.commitment_hash,
        "wrap_protocol" => wrap["protocol"],
        "wrap_version" => wrap["protocol_version"],
        "wrap_purpose" => wrap["purpose"],
        "wrap_resource_hash" => envelope.resource_hash,
        "wrap_body_hash" => envelope.wrap_body_hash,
        "ciphertext_hash" => envelope.ciphertext_hash
      }

      event = key_event(p, seq, "workspace_member_envelope_issued", actor, prev, body)
      {events ++ [event], KeyDirectory.event_hash(event), seq + 1}
    end)
  end

  defp build_invitation_update_events(p, actor, previous_hash, sequence, event_type, updates) do
    Enum.reduce(updates, {[], previous_hash, sequence}, fn update, {events, prev, seq} ->
      body =
        update
        |> Map.take(invitation_event_body_keys(event_type))
        |> Map.put("workspace_id", p.workspace_id)
        |> Map.put("updated_at_event_sequence", seq)
        |> Map.put("update_reason", "workspace_kek_rotation")

      event = key_event(p, seq, event_type, actor, prev, body)
      {events ++ [event], KeyDirectory.event_hash(event), seq + 1}
    end)
  end

  defp invitation_event_body_keys("workspace_invitation_bootstrap_updated"),
    do:
      ~w(invitation_id previous_bootstrap_package_hash bootstrap_package_hash bootstrap_package_key_maintenance_wrap_hash key_version_context)

  defp invitation_event_body_keys("guest_invitation_bootstrap_updated"),
    do:
      ~w(guest_invitation_id scope_kind scope_id previous_bootstrap_package_hash bootstrap_package_hash bootstrap_package_key_maintenance_wrap_hash key_version_context)

  defp completion_actor(p), do: p.business |> Map.get(:device_wraps, []) |> actor_from_wraps(p)

  defp actor_from_wraps([first | _], _p), do: first.wrap["sender"]

  defp actor_from_wraps([], p) do
    %{
      "signer_kind" => "device",
      "user_id" => p.actor_user_id,
      "device_id" => p.actor_device_id,
      "signing_key_id" => p.actor_signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => p.workspace_id,
      "key_checkpoint_sequence" => p.key_checkpoint.sequence,
      "key_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
    }
  end

  defp key_event(p, sequence, event_type, actor, previous_hash, body) do
    KeyDirectory.build_event_payload!(%{
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "sequence" => sequence,
      "event_type" => event_type,
      "actor" => actor,
      "previous_event_hash" => previous_hash,
      "body" => body
    })
  end

  defp wrap_event_body(wrap) do
    %{
      "purpose" => wrap.wrap["purpose"],
      "recipient" => wrap.wrap["recipient"],
      "resource" => wrap.wrap["resource"],
      "resource_hash" => wrap.resource_hash,
      "sender" => wrap.wrap["sender"],
      "wrap_body_hash" => wrap.wrap_body_hash,
      "wrap_protocol" => wrap.wrap["protocol"],
      "wrap_suite_id" => wrap.wrap["suite_id"],
      "wrap_suite_rank" => wrap.wrap["suite_rank"],
      "wrap_version" => wrap.wrap["protocol_version"]
    }
  end

  defp validate_recipe!(%{event_type: "workspace.member.role_changed"} = p, [first]) do
    expected = %{
      "workspace_id" => p.workspace_id,
      "user_id" => p.command["target_user_id"],
      "previous_role_id" => p.business.target_role.id,
      "previous_base_role" => p.business.target_role.base_role,
      "new_role_id" => p.business.new_role.id,
      "new_base_role" => p.business.new_role.base_role
    }

    assert_primary!(first, "member_role_changed", expected)
  end

  defp validate_recipe!(%{event_type: "workspace.member.removed"} = p, payloads) do
    [first | effects] = payloads

    assert_primary!(first, "member_removed", %{
      "workspace_id" => p.workspace_id,
      "user_id" => p.command["target_user_id"]
    })

    {workspace_revocations, effects} =
      Enum.split(effects, length(p.business.workspace_invitations))

    Enum.zip(workspace_revocations, p.business.workspace_invitations)
    |> Enum.each(fn {revocation, invitation} ->
      assert_primary!(revocation, "workspace_invitation_revoked", %{
        "workspace_id" => p.workspace_id,
        "invitation_id" => invitation.id,
        "reason" => "member_removed"
      })
    end)

    {guest_revocations, effects} = Enum.split(effects, length(p.business.guest_invitations))

    Enum.zip(guest_revocations, p.business.guest_invitations)
    |> Enum.each(fn {revocation, invitation} ->
      assert_primary!(revocation, "guest_invitation_revoked", %{
        "workspace_id" => p.workspace_id,
        "guest_invitation_id" => invitation.id,
        "reason" => "member_removed"
      })
    end)

    [kek_rotation | document_rotations] = effects
    workspace = p.business.workspace

    assert_primary!(kek_rotation, "rotation_started", %{
      "event_type" => "rotation_started",
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "old_key_version" => workspace.current_kek_version,
      "new_key_version" => workspace.current_kek_version + 1,
      "reason" => "membership_change"
    })

    unless length(document_rotations) == length(p.business.documents),
      do: raise(ArgumentError, "workspace_authority_mutation_recipe_invalid")

    Enum.zip(document_rotations, p.business.documents)
    |> Enum.each(fn {rotation, document} ->
      assert_primary!(rotation, "rotation_started", %{
        "event_type" => "rotation_started",
        "rotation_kind" => "dek",
        "scope_kind" => "document",
        "scope_id" => document.id,
        "old_key_version" => document.min_dek_version,
        "new_key_version" => document.min_dek_version + 1,
        "reason" => "membership_change"
      })
    end)
  end

  defp validate_recipe!(%{event_type: "workspace.kek.rotation_started"} = p, [first]) do
    assert_primary!(first, "rotation_started", %{
      "event_type" => "rotation_started",
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "old_key_version" => p.command["old_key_version"],
      "new_key_version" => p.command["new_key_version"],
      "reason" => p.command["reason"]
    })
  end

  defp validate_recipe!(%{event_type: "workspace.kek.rotation_completed"} = p, payloads) do
    [completed | effects] = payloads

    assert_primary!(completed, "rotation_completed", %{
      "event_type" => "rotation_completed",
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "old_key_version" => p.command["old_key_version"],
      "new_key_version" => p.command["new_key_version"]
    })

    unless completed["body"]["completion_manifest_hash"] ==
             Directory.completion_manifest_hash(p.business.workspace, p.command, p.business),
           do: raise(ArgumentError, "kek_rotation_completion_manifest_invalid")

    expected_types =
      List.duplicate("wrap_issued", length(p.command["device_wrap_precommits"])) ++
        List.duplicate(
          "workspace_member_envelope_issued",
          length(p.command["member_envelope_precommits"])
        ) ++
        List.duplicate(
          "workspace_invitation_bootstrap_updated",
          length(p.command["workspace_invitation_updates"])
        ) ++
        List.duplicate(
          "guest_invitation_bootstrap_updated",
          length(p.command["guest_invitation_updates"])
        )

    unless Enum.map(effects, & &1["event_type"]) == expected_types,
      do: raise(ArgumentError, "workspace_authority_mutation_recipe_invalid")
  end

  defp validate_recipe!(%{event_type: "workspace.kek.old_key_deleted"} = p, [deleted]) do
    assert_primary!(deleted, "old_key_deleted", %{
      "event_type" => "old_key_deleted",
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => p.workspace_id,
      "old_key_version" => p.command["old_key_version"]
    })

    unless deleted["body"]["deletion_manifest_hash"] == hash(p.command["deletion_manifest"]),
      do: raise(ArgumentError, "kek_rotation_deletion_manifest_invalid")
  end

  defp assert_primary!(payload, event_type, expected) do
    unless payload["event_type"] == event_type and
             Map.take(payload["body"], Map.keys(expected)) == expected do
      raise ArgumentError, "workspace_authority_mutation_recipe_invalid"
    end
  end

  defp audit_event(p, mutation_id, effects_hash, kd) do
    command = %{
      "protocol" => "refmd.audit.high-risk-command",
      "version" => 1,
      "event_type" => p.event_type,
      "mutation_id" => mutation_id,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => p.workspace_id,
      "subject_kind" => subject_kind(p.event_type),
      "subject_id" => subject_id(p),
      "requested_effects" => requested_effects(p.event_type, kd.effects)
    }

    event =
      AuditChainEvent.build!(%{
        "event_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "workspace",
        "chain_scope_id" => p.workspace_id,
        "sequence" => p.audit_head.sequence + 1,
        "previous_event_hash" => p.audit_head.event_hash,
        "event_type" => p.event_type,
        "event_body" => %{
          "protocol" => "refmd.audit.high-risk-mutation",
          "version" => 1,
          "event_type" => p.event_type,
          "mutation_id" => mutation_id,
          "chain_scope_kind" => "workspace",
          "chain_scope_id" => p.workspace_id,
          "actor" => %{
            "kind" => "device",
            "user_id" => p.actor_user_id,
            "device_id" => p.actor_device_id
          },
          "subject_kind" => subject_kind(p.event_type),
          "subject_id" => subject_id(p),
          "canonical_request_hash" => hash(command),
          "key_directory_effects_hash" => effects_hash
        }
      })

    AuditChainEvent.envelope!(event, AuditChainEvent.hash!(event))
  end

  defp requested_effects(event_type, effects) do
    primary =
      effects
      |> hd()
      |> Map.fetch!("event_payload")
      |> Map.fetch!("body")
      |> sequence_placeholders()

    [%{"effect_type" => "authorization:#{event_type}:0", "body" => primary}] ++
      Enum.with_index(effects, fn effect, index ->
        payload = effect["event_payload"]

        %{
          "effect_type" => "key-directory:#{event_type}:#{index}",
          "body" => sequence_placeholders(payload["body"])
        }
      end)
  end

  defp subject_kind(event_type)
       when event_type in [
              "workspace.kek.rotation_started",
              "workspace.kek.rotation_completed",
              "workspace.kek.old_key_deleted"
            ],
       do: "key_rotation"

  defp subject_kind(_), do: "workspace_member"

  defp subject_id(%{event_type: event_type} = p)
       when event_type in [
              "workspace.kek.rotation_started",
              "workspace.kek.rotation_completed",
              "workspace.kek.old_key_deleted"
            ],
       do: p.command["rotation_id"]

  defp subject_id(p), do: p.command["target_user_id"]

  defp sequence_placeholders(body) do
    Map.new(body, fn
      {key, _value}
      when key in [
             "changed_at_event_sequence",
             "removed_at_event_sequence",
             "not_before_event_sequence",
             "completed_at_event_sequence",
             "deleted_at_event_sequence",
             "updated_at_event_sequence"
           ] ->
        {key, "CANDIDATE_SEQUENCE"}

      pair ->
        pair
    end)
  end

  defp requirements(p, kd) do
    event_requirements =
      Enum.map(kd.effects, fn effect ->
        payload = effect["event_payload"]

        transcript =
          Signature.build_key_directory_event_transcript!(
            payload["event_type"],
            "device",
            p.actor_device_id,
            payload
          )

        requirement(
          effect["effect_order"],
          "key_directory_event",
          "key_directory_event",
          payload["event_type"],
          hash(transcript),
          p.actor_signing_key_id
        )
      end)

    transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        "workspace_authorized",
        "device",
        p.actor_device_id,
        kd.checkpoint_payload,
        checkpoint_signer(p)
      )

    checkpoint_requirement =
      requirement(
        length(event_requirements) + 1,
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "workspace_authorized",
        hash(transcript),
        p.actor_signing_key_id
      )

    base = event_requirements ++ [checkpoint_requirement]
    base ++ pq_wrap_requirements(p, kd, length(base) + 1)
  end

  defp pq_wrap_requirements(%{event_type: "workspace.kek.rotation_completed"} = p, kd, order) do
    device_count = length(p.business.device_wraps)

    device =
      p.business.device_wraps
      |> Enum.with_index()
      |> Enum.map(fn {wrap, index} ->
        event = Enum.at(kd.effects, index + 1)

        requirement(
          order + index,
          "pq_wrap",
          "pq_wrap",
          "none",
          hash(pq_wrap_transcript(p, kd, wrap, event)),
          p.actor_signing_key_id
        )
        |> Map.put("precommit_kind", "device_wrap")
        |> Map.put("precommit_index", index)
        |> Map.put("pq_wrap_signing_input", pq_wrap_signing_input(p, kd, wrap, event))
      end)

    member =
      p.business.member_envelopes
      |> Enum.with_index()
      |> Enum.map(fn {envelope, index} ->
        event = Enum.at(kd.effects, 1 + device_count + index)

        requirement(
          order + device_count + index,
          "pq_wrap",
          "pq_wrap",
          "none",
          hash(pq_wrap_transcript(p, kd, envelope, event)),
          p.actor_signing_key_id
        )
        |> Map.put("precommit_kind", "member_envelope")
        |> Map.put("precommit_index", index)
        |> Map.put("pq_wrap_signing_input", pq_wrap_signing_input(p, kd, envelope, event))
      end)

    device ++ member
  end

  defp pq_wrap_requirements(_, _, _), do: []

  defp pq_wrap_transcript(p, kd, wrap, event) do
    input = pq_wrap_signing_input(p, kd, wrap, event)

    Signature.build_pq_wrap_transcript!(
      p.actor_device_id,
      input["actor"],
      input["authority_boundary"],
      input["subject_hashes"]
    )
  end

  defp pq_wrap_signing_input(p, kd, wrap, event) do
    payload = event["event_payload"]
    event_hash = event["event_hash"]
    checkpoint = kd.checkpoint_payload
    covered = checkpoint["covered_event_head"]

    %{
      "actor" => wrap.wrap["sender"],
      "authority_boundary" => %{
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "event_hash" => event_hash,
        "operation_checkpoint_sequence" => checkpoint["sequence"],
        "operation_checkpoint_hash" => kd.checkpoint_hash,
        "covered_event_head_sequence" => covered["head_sequence"],
        "covered_event_head_hash" => covered["head_hash"]
      },
      "subject_hashes" => %{
        "resource_hash" => wrap.resource_hash,
        "wrap_body_hash" => wrap.wrap_body_hash,
        "wrap_event_body_hash" => hash(payload["body"]),
        "wrap_event_hash" => event_hash,
        "hpke_info_hash" => wrap.hpke_info_hash,
        "aad_hash" => wrap.aad_hash
      }
    }
  end

  defp requirement(order, kind, purpose, variant, subject_hash, signer_key_id) do
    %{
      "requirement_order" => order,
      "authorization_kind" => kind,
      "signing_purpose" => purpose,
      "surface_variant" => variant,
      "subject_hash" => subject_hash,
      "signer_key_id" => signer_key_id
    }
  end

  defp global_effects_hash(workspace_id, kd) do
    hash(%{
      "scopes" => [
        %{
          "chain_scope_kind" => "workspace",
          "chain_scope_id" => workspace_id,
          "events" => Enum.map(kd.effects, & &1["event_payload"]),
          "checkpoint" => kd.checkpoint_payload
        }
      ]
    })
  end

  defp string_keys(%{sequence: sequence, event_hash: event_hash}),
    do: %{"sequence" => sequence, "event_hash" => event_hash}

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp error_message(%Ecto.InvalidChangesetError{} = error), do: error.changeset
  defp error_message(%ArgumentError{} = error), do: error.message
end
