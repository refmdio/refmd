defmodule RefMD.Devices.Revocations.Intent do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Devices.Revocations.Prepare
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.State
  alias RefMD.Security.{AuditChainEvent, CompoundAppend}

  def issue(user_id, actor_device_id, device_id, command) do
    prepared = Prepare.validate!(user_id, actor_device_id, device_id, command)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    mutation_id = Ecto.UUID.generate()
    kd = key_directory(prepared, now)
    effects_hash = global_effects_hash(prepared.user_id, kd)
    audit = audit_event(prepared, mutation_id, effects_hash)
    audit_payload = audit_checkpoint_payload(prepared, audit)
    requirements = requirements(prepared, kd, audit)

    scope = %{
      "chain_scope_kind" => "user",
      "chain_scope_id" => prepared.user_id,
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
      "candidate_key_directory_checkpoint_payload" => kd.checkpoint,
      "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash,
      "scope_key_directory_effects_hash" =>
        hash(%{
          "candidate_key_directory_effects" => kd.effects,
          "candidate_key_directory_checkpoint_payload" => kd.checkpoint,
          "candidate_key_directory_checkpoint_hash" => kd.checkpoint_hash
        }),
      "effect_signature_requirements" => requirements,
      "checkpoint_payload_hash" => Audit.checkpoint_hash!("user_device", audit_payload),
      "required_checkpoint_variant" => "user_device"
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
       mutation_kind: "device_revocation_retire",
       actor_user_id: user_id,
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
      "chain_scope_kind" => "user",
      "chain_scope_id" => p.user_id,
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "previous_signed_checkpoint_sequence" => previous["payload"]["sequence"],
      "previous_signed_checkpoint_hash" => previous["checkpoint_hash"],
      "signer_user_id" => p.user_id,
      "signer_device_id" => p.actor_device_id,
      "signing_key_id" => p.actor_signing_key_id,
      "authorization_checkpoint_scope_kind" => "user",
      "authorization_checkpoint_scope_id" => p.user_id,
      "authorization_checkpoint_sequence" => p.key_checkpoint.sequence,
      "authorization_checkpoint_hash" => p.key_checkpoint.checkpoint_hash,
      "covered_event_class" => "authority",
      "covered_event_type" => event["event_type"]
    }
  end

  def revocation_transcript(p, event) do
    Signature.build_device_revocation_transcript!(
      p.actor_device_id,
      %{
        "user_id" => p.user_id,
        "device_id" => p.actor_device_id,
        "signing_key_id" => p.actor_signing_key_id,
        "key_scope_kind" => "user",
        "key_scope_id" => p.user_id,
        "key_checkpoint_sequence" => p.key_checkpoint.sequence,
        "key_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
      },
      %{
        "user_id" => p.user_id,
        "device_id" => p.target_device_id,
        "encryption_key_id" => p.target_encryption_key_id,
        "signing_key_id" => p.target_signing_key_id
      },
      %{
        "revocation_event_sequence" => event["sequence"],
        "revocation_event_hash" => event["event_hash"]
      }
    )
  end

  defp key_directory(p, now) do
    current = p.key_checkpoint.payload
    head = current["covered_event_head"]

    actor = %{
      "signer_kind" => "identity",
      "user_id" => p.user_id,
      "signing_key_id" => p.identity_signing_key_id,
      "key_scope_kind" => "user",
      "key_scope_id" => p.user_id,
      "key_checkpoint_sequence" => p.key_checkpoint.sequence,
      "key_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
    }

    signing =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => p.user_id,
        "sequence" => head["head_sequence"] + 1,
        "previous_event_hash" => head["head_hash"],
        "event_type" => "signing_key_revoked",
        "actor" => actor,
        "body" => %{
          "key_id" => p.target_signing_key_id,
          "reason" => "device_revoked",
          "revoked_at_event_sequence" => head["head_sequence"] + 1
        }
      })

    encryption =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => p.user_id,
        "sequence" => signing["sequence"] + 1,
        "previous_event_hash" => KeyDirectory.event_hash(signing),
        "event_type" => "encryption_key_revoked",
        "actor" => actor,
        "body" => %{
          "key_id" => p.target_encryption_key_id,
          "reason" => "device_revoked",
          "revoked_at_event_sequence" => signing["sequence"] + 1
        }
      })

    checkpoint =
      current
      |> Map.put("sequence", current["sequence"] + 1)
      |> Map.put("issued_at", DateTime.to_iso8601(now))
      |> Map.put("previous_checkpoint_hash", p.key_checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", %{
        "head_sequence" => encryption["sequence"],
        "head_hash" => KeyDirectory.event_hash(encryption)
      })
      |> State.revoke_key_entry!(p.target_signing_key_id, signing)
      |> State.revoke_key_entry!(p.target_encryption_key_id, encryption)

    effects =
      [signing, encryption]
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
      checkpoint: checkpoint,
      checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint)
    }
  end

  defp audit_event(p, mutation_id, effects_hash) do
    event_type = "user.device.revoked.retire"

    command = %{
      "protocol" => "refmd.audit.high-risk-command",
      "version" => 1,
      "event_type" => event_type,
      "mutation_id" => mutation_id,
      "chain_scope_kind" => "user",
      "chain_scope_id" => p.user_id,
      "subject_kind" => "user_device",
      "subject_id" => p.target_device_id,
      "requested_effects" =>
        [
          %{"effect_type" => "authorization:#{event_type}:0", "body" => p.command}
        ] ++
          Enum.with_index(["signing_key_revoked", "encryption_key_revoked"], fn type, index ->
            %{
              "effect_type" => "key-directory:#{event_type}:#{index}",
              "body" =>
                if(type == "signing_key_revoked",
                  do: %{
                    "key_id" => p.target_signing_key_id,
                    "reason" => "device_revoked",
                    "revoked_at_event_sequence" => "CANDIDATE_SEQUENCE"
                  },
                  else: %{
                    "key_id" => p.target_encryption_key_id,
                    "reason" => "device_revoked",
                    "revoked_at_event_sequence" => "CANDIDATE_SEQUENCE"
                  }
                )
            }
          end)
    }

    event =
      AuditChainEvent.build!(%{
        "event_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "user",
        "chain_scope_id" => p.user_id,
        "sequence" => p.audit_head.sequence + 1,
        "previous_event_hash" => p.audit_head.event_hash,
        "event_type" => event_type,
        "event_body" => %{
          "protocol" => "refmd.audit.high-risk-mutation",
          "version" => 1,
          "event_type" => event_type,
          "mutation_id" => mutation_id,
          "chain_scope_kind" => "user",
          "chain_scope_id" => p.user_id,
          "actor" => %{
            "kind" => "device",
            "user_id" => p.user_id,
            "device_id" => p.actor_device_id
          },
          "subject_kind" => "user_device",
          "subject_id" => p.target_device_id,
          "canonical_request_hash" => hash(command),
          "key_directory_effects_hash" => effects_hash
        }
      })

    AuditChainEvent.envelope!(event, AuditChainEvent.hash!(event))
  end

  defp requirements(p, kd, audit) do
    event_requirements =
      Enum.map(kd.effects, fn effect ->
        payload = effect["event_payload"]

        transcript =
          Signature.build_key_directory_event_transcript!(
            payload["event_type"],
            "identity",
            p.user_id,
            payload
          )

        requirement(
          effect["effect_order"],
          "key_directory_event",
          "key_directory_event",
          payload["event_type"],
          hash(transcript),
          p.identity_signing_key_id
        )
      end)

    signer = %{
      "signer_kind" => "identity",
      "user_id" => p.user_id,
      "signing_key_id" => p.identity_signing_key_id,
      "authorizing_checkpoint_sequence" => p.key_checkpoint.sequence,
      "authorizing_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
    }

    checkpoint_transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        "identity_active",
        "identity",
        p.user_id,
        kd.checkpoint,
        signer
      )

    event_requirements ++
      [
        requirement(
          3,
          "key_directory_checkpoint",
          "key_directory_checkpoint",
          "identity_active",
          hash(checkpoint_transcript),
          p.identity_signing_key_id
        ),
        requirement(
          4,
          "device_revocation",
          "device_revocation",
          "none",
          hash(revocation_transcript(p, audit)),
          p.actor_signing_key_id
        )
      ]
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

  defp global_effects_hash(user_id, kd) do
    hash(%{
      "scopes" => [
        %{
          "chain_scope_kind" => "user",
          "chain_scope_id" => user_id,
          "events" => Enum.map(kd.effects, & &1["event_payload"]),
          "checkpoint" => kd.checkpoint
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
