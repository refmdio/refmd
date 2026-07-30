defmodule RefMD.Security.SignedAuditCheckpoints do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Signature
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Authority
  alias RefMD.Repo
  alias RefMD.Security.{AuditChainEvent, AuditEvent, SignedAuditCheckpoint}

  @variants ~w(user_identity user_device workspace_device workspace_guest_device)
  @user_identity_events ~w(
    user.identity.key_added user.identity.signing_key_revoked
    user.identity.encryption_key_revoked user.identity.rotation_started
    user.identity.rotation_completed user.identity.old_key_deleted
    user.recovery_authorization.created user.recovery_authorization.replaced
    user.device.recovery_approved user.suite_policy.changed
  )
  @user_device_events ~w(
    user.device.approved user.device.revoked.security user.device.revoked.retire
    user.trust_transfer.completed
  )

  def insert!(envelope, opts) when is_map(envelope) and is_list(opts) do
    assert_envelope_keys!(envelope)
    payload = Map.fetch!(envelope, "payload")
    signature = Map.fetch!(envelope, "signature")
    checkpoint_hash = Map.fetch!(envelope, "checkpoint_hash")
    variant = variant!(payload)

    unless variant in @variants, do: raise(ArgumentError, "audit_checkpoint_variant_invalid")

    Audit.assert_payload!(variant, payload)

    unless checkpoint_hash == Audit.checkpoint_hash!(variant, payload),
      do: raise(ArgumentError, "audit_checkpoint_hash_mismatch")

    assert_event_head!(payload)
    assert_previous_signed_checkpoint!(payload)

    public_key_material = public_key_material!(variant, payload, opts)
    owner_kind = if variant == "user_identity", do: "identity", else: "device"

    owner_id =
      if owner_kind == "identity",
        do: payload["signer_user_id"],
        else: payload["signer_device_id"]

    assert_signer_authority!(variant, payload, public_key_material, owner_kind, owner_id, opts)

    transcript =
      Audit.build_audit_checkpoint_transcript!(variant, owner_kind, owner_id, payload)

    case Signature.verify_hybrid_signature_result(
           "audit_checkpoint",
           transcript,
           signature,
           public_key_material,
           %{checkpoint_payload: payload, authority_verified: true}
         ) do
      :ok -> :ok
      {:error, reason} -> raise ArgumentError, "audit_checkpoint_signature_invalid:#{reason}"
    end

    %SignedAuditCheckpoint{}
    |> SignedAuditCheckpoint.changeset(%{
      chain_scope_kind: payload["chain_scope_kind"],
      chain_scope_id: payload["chain_scope_id"],
      sequence: payload["sequence"],
      event_hash: payload["event_hash"],
      previous_signed_checkpoint_sequence: payload["previous_signed_checkpoint_sequence"],
      previous_signed_checkpoint_hash: payload["previous_signed_checkpoint_hash"],
      signer_user_id: payload["signer_user_id"],
      signer_device_id: payload["signer_device_id"],
      signing_key_id: payload["signing_key_id"],
      authorization_checkpoint_scope_kind: payload["authorization_checkpoint_scope_kind"],
      authorization_checkpoint_scope_id: payload["authorization_checkpoint_scope_id"],
      authorization_checkpoint_sequence: payload["authorization_checkpoint_sequence"],
      authorization_checkpoint_hash: payload["authorization_checkpoint_hash"],
      covered_event_class: payload["covered_event_class"],
      covered_event_type: payload["covered_event_type"],
      variant: variant,
      checkpoint_hash: checkpoint_hash,
      payload: payload,
      signature: signature
    })
    |> Repo.insert!()
  end

  def insert!(_, _), do: raise(ArgumentError, "signed_audit_checkpoint_invalid")

  def current(scope_kind, scope_id)
      when scope_kind in ["user", "workspace"] and is_binary(scope_id) do
    SignedAuditCheckpoint
    |> where([c], c.chain_scope_kind == ^scope_kind and c.chain_scope_id == ^scope_id)
    |> order_by([c], desc: c.sequence)
    |> limit(1)
    |> Repo.one()
  end

  def current(_, _), do: nil

  def bundle(scope_kind, scope_id) when scope_kind in ["user", "workspace"] do
    chain_scope = "#{scope_kind}:#{scope_id}"

    with %SignedAuditCheckpoint{} = checkpoint <- current(scope_kind, scope_id),
         %AuditEvent{} = head <- latest_event(chain_scope) do
      ancestry = events_after(chain_scope, 0)
      assert_valid_ancestry!(ancestry, checkpoint, head)
      signed_ancestry = Enum.filter(ancestry, &(&1.sequence <= checkpoint.sequence))
      tail = Enum.filter(ancestry, &(&1.sequence > checkpoint.sequence))

      %{
        signed_checkpoint: SignedAuditCheckpoint.envelope(checkpoint),
        ancestry: Enum.map(signed_ancestry, &event_envelope/1),
        current_event_head: %{sequence: head.sequence, event_hash: head.event_hash},
        unsigned_tail: Enum.map(tail, &event_envelope/1)
      }
    else
      _ -> {:error, :signed_audit_checkpoint_missing}
    end
  end

  defp assert_envelope_keys!(envelope) do
    unless Enum.sort(Map.keys(envelope)) == ~w(checkpoint_hash payload signature),
      do: raise(ArgumentError, "signed_audit_checkpoint_keys_invalid")
  end

  defp assert_event_head!(payload) do
    chain_scope = "#{payload["chain_scope_kind"]}:#{payload["chain_scope_id"]}"

    event =
      Repo.get_by(AuditEvent,
        chain_scope: chain_scope,
        sequence: payload["sequence"],
        event_hash: payload["event_hash"]
      )

    if match?(%AuditEvent{}, event) and event.class == payload["covered_event_class"] and
         event.type == payload["covered_event_type"] and
         event.actor["user_id"] == payload["signer_user_id"] and
         actor_device_matches?(event.actor, payload),
       do: :ok,
       else: raise(ArgumentError, "audit_checkpoint_event_head_mismatch")
  end

  defp actor_device_matches?(actor, %{"signer_device_id" => device_id}),
    do: actor["device_id"] == device_id

  defp actor_device_matches?(actor, _payload), do: is_nil(actor["device_id"])

  defp assert_previous_signed_checkpoint!(payload)
       when not is_map_key(payload, "previous_signed_checkpoint_sequence") and
              not is_map_key(payload, "previous_signed_checkpoint_hash") do
    case current(payload["chain_scope_kind"], payload["chain_scope_id"]) do
      nil -> :ok
      %SignedAuditCheckpoint{} -> raise ArgumentError, "audit_checkpoint_previous_mismatch"
    end
  end

  defp assert_previous_signed_checkpoint!(payload) do
    previous = current(payload["chain_scope_kind"], payload["chain_scope_id"])

    if match?(%SignedAuditCheckpoint{}, previous) and
         previous.sequence == payload["previous_signed_checkpoint_sequence"] and
         previous.checkpoint_hash == payload["previous_signed_checkpoint_hash"],
       do: :ok,
       else: raise(ArgumentError, "audit_checkpoint_previous_mismatch")
  end

  defp public_key_material!(variant, %{"authorization_checkpoint_sequence" => 0} = payload, opts) do
    variant
    |> genesis_candidate_authority!(payload, opts)
    |> Map.fetch!(:public_key_material)
  end

  defp public_key_material!(_variant, payload, _opts) do
    case KeyDirectory.active_key_material_at_checkpoint(
           payload["authorization_checkpoint_scope_kind"],
           payload["authorization_checkpoint_scope_id"],
           payload["signing_key_id"],
           payload["authorization_checkpoint_sequence"],
           payload["authorization_checkpoint_hash"]
         ) do
      {:ok, material} -> material
      {:error, :not_found} -> raise ArgumentError, "audit_checkpoint_signer_unknown"
    end
  end

  defp variant!(%{"chain_scope_kind" => "user"} = payload) do
    if Map.has_key?(payload, "signer_device_id"), do: "user_device", else: "user_identity"
  end

  defp variant!(%{
         "chain_scope_kind" => "workspace",
         "covered_event_type" => "workspace.guest_invitation.redeemed." <> _
       }),
       do: "workspace_guest_device"

  defp variant!(%{"chain_scope_kind" => "workspace"}), do: "workspace_device"
  defp variant!(_), do: raise(ArgumentError, "audit_checkpoint_variant_invalid")

  defp assert_signer_authority!(
         variant,
         payload,
         public_key_material,
         owner_kind,
         owner_id,
         opts
       ) do
    unless public_key_material["owner_kind"] == owner_kind and
             public_key_material["owner_id"] == owner_id and
             Signature.compute_signing_key_id!(public_key_material) == payload["signing_key_id"] do
      raise ArgumentError, "audit_checkpoint_signer_owner_mismatch"
    end

    assert_variant_authority!(variant, payload, opts)
  end

  defp assert_variant_authority!(
         variant,
         %{"authorization_checkpoint_sequence" => 0} = payload,
         opts
       ) do
    genesis_candidate_authority!(variant, payload, opts)
    :ok
  end

  defp assert_variant_authority!("user_identity", payload, _opts) do
    assert_literal!(payload["signer_user_id"], payload["chain_scope_id"])
    assert_event_type_in!(payload["covered_event_type"], @user_identity_events)
  end

  defp assert_variant_authority!("user_device", payload, _opts) do
    assert_literal!(payload["signer_user_id"], payload["chain_scope_id"])
    assert_event_type_in!(payload["covered_event_type"], @user_device_events)
  end

  defp assert_variant_authority!("workspace_device", payload, _opts) do
    case audit_authorization_event_head(payload) do
      {:ok, event_head_sequence} ->
        Authority.assert_audit_checkpoint_authority!(
          payload["chain_scope_id"],
          event_head_sequence,
          payload["covered_event_type"],
          %{
            "signer_kind" => "device",
            "user_id" => payload["signer_user_id"],
            "device_id" => payload["signer_device_id"],
            "signing_key_id" => payload["signing_key_id"]
          }
        )

      _ ->
        raise ArgumentError, "audit_checkpoint_authority_unverified"
    end
  end

  defp assert_variant_authority!("workspace_guest_device", payload, opts) do
    with {:ok, event_head_sequence} <-
           KeyDirectory.checkpoint_event_head(
             payload["authorization_checkpoint_scope_kind"],
             payload["authorization_checkpoint_scope_id"],
             payload["authorization_checkpoint_sequence"],
             payload["authorization_checkpoint_hash"]
           ),
         true <-
           Authority.active_workspace_scope_guest_device_admitted?(
             payload["chain_scope_id"],
             event_head_sequence,
             payload["signer_user_id"],
             payload["signer_device_id"]
           ),
         :ok <- assert_guest_self_admission_authority!(payload, opts) do
      :ok
    else
      _ -> raise ArgumentError, "audit_checkpoint_authority_unverified"
    end
  end

  defp assert_guest_self_admission_authority!(payload, opts) do
    authority = Keyword.fetch!(opts, :self_admission_authority)

    expected_keys =
      ~w(compound_intent_id invitation_id mutation_id resulting_checkpoint_hash
         signer_device_id signer_user_id workspace_id)a

    unless is_map(authority) and Enum.sort(Map.keys(authority)) == Enum.sort(expected_keys),
      do: raise(ArgumentError, "audit_checkpoint_self_admission_authority_invalid")

    assert_literal!(authority.workspace_id, payload["chain_scope_id"])
    assert_literal!(authority.signer_user_id, payload["signer_user_id"])
    assert_literal!(authority.signer_device_id, payload["signer_device_id"])
    assert_literal!(authority.resulting_checkpoint_hash, payload["authorization_checkpoint_hash"])
    assert_uuid!(authority.compound_intent_id)
    assert_uuid!(authority.mutation_id)
    assert_uuid!(authority.invitation_id)
    :ok
  end

  defp audit_authorization_event_head(payload) do
    KeyDirectory.checkpoint_event_head(
      payload["authorization_checkpoint_scope_kind"],
      payload["authorization_checkpoint_scope_id"],
      payload["authorization_checkpoint_sequence"],
      payload["authorization_checkpoint_hash"]
    )
  end

  defp genesis_candidate_authority!(variant, payload, opts) do
    authority = Keyword.fetch!(opts, :genesis_candidate_authority)

    unless is_map(authority) and
             Enum.sort(Map.keys(authority)) ==
               Enum.sort([
                 :chain_scope_id,
                 :chain_scope_kind,
                 :public_key_material,
                 :signer_device_id,
                 :signer_user_id
               ]),
           do: raise(ArgumentError, "audit_checkpoint_genesis_authority_invalid")

    expected_event_type =
      case variant do
        "user_identity" -> "user.device.genesis_bootstrapped"
        "workspace_device" -> "workspace.genesis"
        _ -> raise ArgumentError, "audit_checkpoint_genesis_variant_invalid"
      end

    assert_literal!(authority.chain_scope_kind, payload["chain_scope_kind"])
    assert_literal!(authority.chain_scope_id, payload["chain_scope_id"])
    assert_literal!(authority.signer_user_id, payload["signer_user_id"])
    assert_literal!(authority.signer_device_id, payload["signer_device_id"])
    assert_literal!(payload["covered_event_type"], expected_event_type)
    authority
  end

  defp assert_literal!(value, value), do: :ok
  defp assert_literal!(_, _), do: raise(ArgumentError, "audit_checkpoint_authority_unverified")

  defp assert_event_type_in!(event_type, allowed) do
    unless event_type in allowed,
      do: raise(ArgumentError, "audit_checkpoint_authority_unverified")
  end

  defp assert_uuid!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, ^value} -> :ok
      _ -> raise ArgumentError, "audit_checkpoint_self_admission_authority_invalid"
    end
  end

  defp latest_event(chain_scope) do
    AuditEvent
    |> where([e], e.chain_scope == ^chain_scope)
    |> order_by([e], desc: e.sequence)
    |> limit(1)
    |> Repo.one()
  end

  defp events_after(chain_scope, sequence) do
    Repo.all(
      from(e in AuditEvent,
        where: e.chain_scope == ^chain_scope and e.sequence > ^sequence,
        order_by: [asc: e.sequence]
      )
    )
  end

  defp event_envelope(event) do
    event
    |> Map.from_struct()
    |> AuditChainEvent.build!()
    |> AuditChainEvent.envelope!(event.event_hash)
  end

  defp assert_valid_ancestry!(events, checkpoint, head) do
    final_hash =
      events
      |> Enum.with_index(1)
      |> Enum.reduce("GENESIS", fn {event, expected_sequence}, previous_hash ->
        canonical_event = event |> Map.from_struct() |> AuditChainEvent.build!()

        unless event.sequence == expected_sequence and
                 event.previous_event_hash == previous_hash and
                 event.event_hash == AuditChainEvent.hash!(canonical_event) do
          raise ArgumentError, "audit_chain_invalid"
        end

        event.event_hash
      end)

    checkpoint_event = Enum.at(events, checkpoint.sequence - 1)

    unless match?(%AuditEvent{}, checkpoint_event) and
             checkpoint_event.event_hash == checkpoint.event_hash and
             head.sequence == length(events) and head.event_hash == final_hash do
      raise ArgumentError, "audit_chain_invalid"
    end
  end
end
