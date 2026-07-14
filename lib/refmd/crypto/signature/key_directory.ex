defmodule RefMD.Crypto.Signature.KeyDirectory do
  @moduledoc false

  @protocol_version 1
  @suite_rank 1000

  @key_directory_event_variants [
    "device_key_added",
    "encryption_key_revoked",
    "identity_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "document_snapshot_accepted",
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
    "signing_key_revoked",
    "suite_policy_changed",
    "wrap_issued"
  ]

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4, transcript_base: 4]

  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.SigningSurface

  def build_key_directory_checkpoint_transcript!(
        variant,
        owner_kind,
        owner_id,
        checkpoint_payload,
        signer \\ nil
      )

  def build_key_directory_checkpoint_transcript!(
        variant,
        owner_kind,
        owner_id,
        checkpoint_payload,
        signer
      )
      when variant in [
             "identity_initial",
             "workspace_initial",
             "identity_active",
             "identity_rotation",
             "workspace_authorized",
             "invitation_redeem_authority",
             "share_participant_document_operation",
             "device_authorized"
           ] and
             is_binary(owner_kind) and is_binary(owner_id) and is_map(checkpoint_payload) do
    surface = SigningSurface.get_active!("key_directory_checkpoint", variant)

    subject = JCS.canonical_bytes!(checkpoint_payload)
    covered_head = checkpoint_payload["covered_event_head"]
    sequence = checkpoint_payload["sequence"]

    scope = %{
      "scope_kind" => checkpoint_payload["scope_kind"],
      "scope_id" => checkpoint_payload["scope_id"],
      "checkpoint_sequence" => sequence,
      "covered_event_head_sequence" => covered_head["head_sequence"],
      "covered_event_head_hash" => covered_head["head_hash"]
    }

    scope =
      if sequence == 1 do
        scope
      else
        Map.put(
          scope,
          "previous_checkpoint_hash",
          required_string!(checkpoint_payload["previous_checkpoint_hash"])
        )
      end

    signer = signer || required_map!(checkpoint_payload["signer"])

    transcript =
      transcript_base("key_directory_checkpoint", surface, owner_kind, owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(subject),
        "subject_protocol" => "refmd.key-directory-checkpoint",
        "subject_version" => @protocol_version,
        "scope" => scope,
        "signer" => signer,
        "authority_boundary" => checkpoint_authority_boundary!(sequence, signer),
        "suite_policy" => %{
          "suite_policy_version" => checkpoint_payload["suite_policy_version"],
          "min_suite_rank" => checkpoint_payload["min_suite_rank"],
          "allowed_suite_ids_hash" =>
            Hash.blake3_base64url(
              JCS.canonical_bytes!(%{
                "allowed_suite_ids" => checkpoint_payload["allowed_suite_ids"]
              })
            )
        }
      })

    assert_transcript!(transcript, "key_directory_checkpoint", owner_kind, owner_id)
    transcript
  end

  def build_key_directory_checkpoint_transcript!(_, _, _, _, _),
    do: raise(ArgumentError, "key_directory_checkpoint_transcript_invalid")

  def build_key_directory_event_transcript!(event_type, owner_kind, owner_id, event_payload)
      when event_type in @key_directory_event_variants and is_binary(owner_kind) and
             is_binary(owner_id) and is_map(event_payload) do
    surface = SigningSurface.get_active!("key_directory_event", event_type)

    subject = JCS.canonical_bytes!(event_payload)
    sequence = event_payload["sequence"]

    event = %{
      "event_body_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(event_payload["body"])),
      "event_type" => event_payload["event_type"],
      "scope_id" => event_payload["scope_id"],
      "scope_kind" => event_payload["scope_kind"],
      "sequence" => sequence
    }

    event =
      if sequence == 1 do
        event
      else
        Map.put(
          event,
          "previous_event_hash",
          required_string!(event_payload["previous_event_hash"])
        )
      end

    transcript =
      transcript_base("key_directory_event", surface, owner_kind, owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(subject),
        "subject_protocol" => "refmd.key-directory-event",
        "subject_version" => @protocol_version,
        "event" => event,
        "actor" => required_map!(event_payload["actor"]),
        "authority_boundary" => event_authority_boundary!(event_payload)
      })

    assert_transcript!(transcript, "key_directory_event", owner_kind, owner_id)
    transcript
  end

  def build_key_directory_event_transcript!(_, _, _, _),
    do: raise(ArgumentError, "key_directory_event_transcript_invalid")

  defp checkpoint_authority_boundary!(1, _signer), do: %{"required_authority" => "tofu_root"}

  defp checkpoint_authority_boundary!(
         _sequence,
         %{"signer_kind" => "invitation_redeem_authority", "invitation_id" => invitation_id}
       )
       when is_binary(invitation_id) do
    %{
      "required_authority" => "invitation_redeem_authority",
      "invitation_id" => invitation_id
    }
  end

  defp checkpoint_authority_boundary!(sequence, signer)
       when is_integer(sequence) and sequence > 1 do
    %{
      "required_authority" => "checkpoint_authorized",
      "authorizing_checkpoint_sequence" =>
        required_integer!(signer["authorizing_checkpoint_sequence"]),
      "authorizing_checkpoint_hash" => required_string!(signer["authorizing_checkpoint_hash"])
    }
  end

  defp checkpoint_authority_boundary!(_, _),
    do: raise(ArgumentError, "key_directory_checkpoint_authority_boundary_invalid")

  defp event_authority_boundary!(%{
         "event_type" => event_type,
         "actor" => actor,
         "scope_kind" => scope_kind,
         "scope_id" => scope_id,
         "sequence" => sequence
       })
       when is_binary(event_type) and is_map(actor) and is_binary(scope_kind) and
              is_binary(scope_id) do
    event_authority_boundary_for_actor!(actor, scope_kind, scope_id, sequence, event_type)
  end

  defp event_authority_boundary!(_),
    do: raise(ArgumentError, "key_directory_event_authority_boundary_invalid")

  defp event_authority_boundary_for_actor!(actor, scope_kind, scope_id, _sequence, _event_type)
       when is_map_key(actor, "key_checkpoint_sequence") and
              is_map_key(actor, "key_checkpoint_hash") do
    %{
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "checkpoint_sequence" => required_integer!(actor["key_checkpoint_sequence"]),
      "checkpoint_hash" => required_string!(actor["key_checkpoint_hash"]),
      "required_authority" => "event_type_authorized_actor"
    }
  end

  defp event_authority_boundary_for_actor!(
         %{"signer_kind" => "invitation_redeem_authority", "invitation_id" => invitation_id},
         _scope_kind,
         _scope_id,
         _sequence,
         event_type
       )
       when is_binary(invitation_id) and is_binary(event_type) do
    %{
      "required_authority" => "invitation_redeem_authority",
      "invitation_id" => invitation_id,
      "event_type" => event_type
    }
  end

  defp event_authority_boundary_for_actor!(_actor, _scope_kind, _scope_id, 1, _event_type),
    do: %{"required_authority" => "tofu_root"}

  defp event_authority_boundary_for_actor!(_, _, _, _, _),
    do: raise(ArgumentError, "key_directory_event_authority_boundary_invalid")

  defp required_map!(value) when is_map(value), do: value
  defp required_map!(_), do: raise(ArgumentError, "key_directory_transcript_required_map_missing")

  defp required_string!(value) when is_binary(value) and byte_size(value) > 0, do: value

  defp required_string!(_),
    do: raise(ArgumentError, "key_directory_transcript_required_field_missing")

  defp required_integer!(value) when is_integer(value) and value >= 1, do: value

  defp required_integer!(_),
    do: raise(ArgumentError, "key_directory_transcript_required_field_missing")

  def build_workspace_pin_bootstrap_transcript!(owner_device_id, workspace_id, bootstrap)
      when is_binary(owner_device_id) and is_binary(workspace_id) and is_map(bootstrap) do
    surface = SigningSurface.get_active!("workspace_pin_bootstrap", "none")
    subject = JCS.canonical_bytes!(bootstrap)

    transcript =
      transcript_base("workspace_pin_bootstrap", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(subject),
        "subject_protocol" => "refmd.workspace-pin-bootstrap",
        "subject_version" => @protocol_version,
        "actor" => required_map!(bootstrap["issuer"]),
        "authority_boundary" => %{
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "checkpoint_sequence" => required_integer!(bootstrap["checkpoint_sequence"]),
          "checkpoint_hash" => required_string!(bootstrap["checkpoint_hash"]),
          "event_head_sequence" => required_integer!(bootstrap["event_head_sequence"]),
          "event_head_hash" => required_string!(bootstrap["event_head_hash"]),
          "issuing_event_hash" => required_string!(bootstrap["issuing_event_hash"])
        },
        "suite_policy" => %{
          "suite_policy_version" => required_integer!(bootstrap["suite_policy_version"]),
          "min_suite_rank" => required_integer!(bootstrap["min_suite_rank"]),
          "allowed_suite_ids_hash" => required_string!(bootstrap["allowed_suite_ids_hash"])
        }
      })

    assert_transcript!(transcript, "workspace_pin_bootstrap", "device", owner_device_id)
    transcript
  end

  def build_workspace_pin_bootstrap_transcript!(_, _, _),
    do: raise(ArgumentError, "workspace_pin_bootstrap_transcript_invalid")

  def build_pq_wrap_transcript!(owner_device_id, actor, authority_boundary, subject_hashes)
      when is_binary(owner_device_id) and is_map(actor) and is_map(authority_boundary) and
             is_map(subject_hashes) do
    surface = SigningSurface.get_active!("pq_wrap", "none")

    transcript =
      transcript_base("pq_wrap", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_protocol" => "refmd.signed-pq-hybrid-wrap",
        "subject_version" => @protocol_version,
        "subject_suite_id" =>
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
        "subject_suite_rank" => @suite_rank,
        "actor" => actor,
        "authority_boundary" => authority_boundary,
        "subject_hashes" => subject_hashes
      })

    assert_transcript!(transcript, "pq_wrap", "device", owner_device_id)
    transcript
  end

  def build_pq_wrap_transcript!(_, _, _, _),
    do: raise(ArgumentError, "pq_wrap_transcript_invalid")

  def build_initial_key_delivery_transcript!(
        owner_device_id,
        variant,
        delivery_signing_body,
        sender,
        recipient,
        ake,
        delivery,
        authority
      )
      when is_binary(owner_device_id) and is_binary(variant) and
             is_map(delivery_signing_body) and is_map(sender) and is_map(recipient) and
             is_map(ake) and is_map(delivery) and is_map(authority) do
    surface = SigningSurface.get_active!("initial_key_delivery", variant)

    transcript =
      transcript_base("initial_key_delivery", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(delivery_signing_body)),
        "subject_protocol" => "refmd.initial-key-delivery",
        "subject_version" => @protocol_version,
        "suite" => %{
          "ake_suite_id" => "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
          "ake_suite_rank" => @suite_rank,
          "initial_delivery_suite_id" => "refmd-v2-initial-delivery-xchacha20poly1305",
          "initial_delivery_suite_rank" => @suite_rank
        },
        "sender" => sender,
        "recipient" => recipient,
        "ake" => ake,
        "delivery" => delivery,
        "authority" => authority
      })

    assert_transcript!(transcript, "initial_key_delivery", "device", owner_device_id)
    transcript
  end

  def build_initial_key_delivery_transcript!(_, _, _, _, _, _, _, _),
    do: raise(ArgumentError, "initial_key_delivery_transcript_invalid")

  def build_initiator_ake_commitment_transcript!(
        owner_device_id,
        commitment_payload,
        initiator,
        ake_inputs,
        binding
      )
      when is_binary(owner_device_id) and is_map(commitment_payload) and is_map(initiator) and
             is_map(ake_inputs) and is_map(binding) do
    surface = SigningSurface.get_active!("initiator_ake_commitment", "none")

    transcript =
      transcript_base("initiator_ake_commitment", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(commitment_payload)),
        "subject_protocol" => "refmd.initiator-ake-commitment",
        "subject_version" => @protocol_version,
        "suite" => %{
          "ake_suite_id" => "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
          "ake_suite_rank" => @suite_rank,
          "initial_delivery_suite_id" => "refmd-v2-initial-delivery-xchacha20poly1305",
          "initial_delivery_suite_rank" => @suite_rank
        },
        "initiator" => initiator,
        "ake_inputs" => ake_inputs,
        "binding" => binding
      })

    assert_transcript!(transcript, "initiator_ake_commitment", "device", owner_device_id)
    transcript
  end

  def build_initiator_ake_commitment_transcript!(_, _, _, _, _),
    do: raise(ArgumentError, "initiator_ake_commitment_transcript_invalid")

  def build_responder_prekey_transcript!(owner_device_id, prekey_payload, responder, freshness)
      when is_binary(owner_device_id) and is_map(prekey_payload) and is_map(responder) and
             is_map(freshness) do
    surface = SigningSurface.get_active!("responder_prekey", "none")

    transcript =
      transcript_base("responder_prekey", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(prekey_payload)),
        "subject_protocol" => "refmd.responder-prekey",
        "subject_version" => @protocol_version,
        "responder" => responder,
        "freshness" => freshness
      })

    assert_transcript!(transcript, "responder_prekey", "device", owner_device_id)
    transcript
  end

  def build_responder_prekey_transcript!(_, _, _, _),
    do: raise(ArgumentError, "responder_prekey_transcript_invalid")

  def build_pin_gossip_statement_transcript!(owner_device_id, pin_gossip)
      when is_binary(owner_device_id) and is_map(pin_gossip) do
    surface = SigningSurface.get_active!("pin_gossip_statement", "none")
    subject = JCS.canonical_bytes!(pin_gossip)

    transcript =
      transcript_base("pin_gossip_statement", surface, "device", owner_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(subject),
        "subject_protocol" => "refmd.pin.gossip_statement",
        "subject_version" => @protocol_version,
        "pin_gossip" => %{
          "statement_hash" => Hash.blake3_base64url(subject),
          "statement" => pin_gossip
        }
      })

    assert_transcript!(transcript, "pin_gossip_statement", "device", owner_device_id)
    transcript
  end

  def build_pin_gossip_statement_transcript!(_, _),
    do: raise(ArgumentError, "pin_gossip_statement_transcript_invalid")
end
