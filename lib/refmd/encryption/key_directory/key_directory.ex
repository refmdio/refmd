defmodule RefMD.Encryption.KeyDirectory do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Suite

  alias RefMD.Encryption.KeyDirectory.{
    Assertions,
    Checkpoint,
    Envelope,
    Event,
    Payload,
    Protocol,
    Replay,
    Signatures,
    Store
  }

  alias RefMD.Encryption.KeyDirectory.Authority, as: Authority
  alias RefMD.Encryption.KeyDirectory.Semantics, as: Semantics
  alias RefMD.Encryption.KeyDirectory.State, as: State
  alias RefMD.Repo

  @protocol_version 1
  @event_protocol "refmd.key-directory-event"
  @checkpoint_protocol "refmd.key-directory-checkpoint"
  @valid_scope_kinds ["user", "workspace"]

  @doc "Key-directory package boundary for supported event type literals."
  def event_types, do: Payload.event_types()

  @doc "Key-directory package boundary for canonical event payload hashing."
  def event_hash(payload), do: Protocol.event_hash(payload)

  @doc "Key-directory package boundary for canonical event body hashing."
  def event_body_hash(body), do: Protocol.event_body_hash(body)

  @doc "Key-directory package boundary for canonical checkpoint payload hashing."
  def checkpoint_hash(payload), do: Protocol.checkpoint_hash(payload)

  def active_workspace_scope_guest_device_admitted?(workspace_id, user_id, device_id)
      when is_binary(workspace_id) and is_binary(user_id) and is_binary(device_id) do
    case current_checkpoint("workspace", workspace_id) do
      %{covered_event_head_sequence: event_head_sequence} ->
        Authority.active_workspace_scope_guest_device_admitted?(
          workspace_id,
          event_head_sequence,
          user_id,
          device_id
        )

      _ ->
        false
    end
  end

  def active_workspace_scope_guest_device_admitted?(_, _, _), do: false

  def build_event_payload!(attrs) when is_map(attrs) do
    payload =
      %{
        "protocol" => @event_protocol,
        "version" => @protocol_version,
        "scope_kind" => Map.fetch!(attrs, "scope_kind"),
        "scope_id" => Map.fetch!(attrs, "scope_id"),
        "sequence" => Map.fetch!(attrs, "sequence"),
        "event_type" => Map.fetch!(attrs, "event_type"),
        "actor" => Map.fetch!(attrs, "actor"),
        "body" => Map.fetch!(attrs, "body")
      }
      |> Assertions.maybe_put("previous_event_hash", Map.get(attrs, "previous_event_hash"))

    Payload.assert_event_payload!(payload)
    payload
  end

  def build_checkpoint_payload!(attrs) when is_map(attrs) do
    policy = Suite.current_suite_policy()

    payload =
      %{
        "protocol" => @checkpoint_protocol,
        "version" => @protocol_version,
        "scope_kind" => Map.fetch!(attrs, "scope_kind"),
        "scope_id" => Map.fetch!(attrs, "scope_id"),
        "sequence" => Map.fetch!(attrs, "sequence"),
        "issued_at" => Map.fetch!(attrs, "issued_at"),
        "suite_policy_version" => policy["suite_policy_version"],
        "min_suite_rank" => policy["min_suite_rank"],
        "allowed_suite_ids" => policy["allowed_suite_ids"],
        "required_components" => policy["required_components"],
        "identity_keys" => Map.get(attrs, "identity_keys", []),
        "device_keys" => Map.get(attrs, "device_keys", []),
        "share_participant_keys" => Map.get(attrs, "share_participant_keys", []),
        "revoked_key_ids" => Map.get(attrs, "revoked_key_ids", []),
        "covered_event_head" =>
          Assertions.normalize_event_head!(Map.fetch!(attrs, "covered_event_head"))
      }
      |> Assertions.maybe_put(
        "previous_checkpoint_hash",
        Map.get(attrs, "previous_checkpoint_hash")
      )

    Payload.assert_checkpoint_payload!(payload)
    payload
  end

  def insert_signed_initial_scope!(
        scope_kind,
        scope_id,
        event_envelopes,
        checkpoint_envelope,
        opts \\ []
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_list(event_envelopes) and
             is_map(checkpoint_envelope) do
    case Repo.transaction(fn ->
           do_insert_signed_initial_scope!(
             scope_kind,
             scope_id,
             event_envelopes,
             checkpoint_envelope,
             opts
           )
         end) do
      {:ok, result} -> result
      {:error, reason} -> raise ArgumentError, inspect(reason)
    end
  end

  defp do_insert_signed_initial_scope!(
         scope_kind,
         scope_id,
         event_envelopes,
         checkpoint_envelope,
         opts
       ) do
    expected_signer_kind = Keyword.fetch!(opts, :checkpoint_signer_kind)
    verify_complete_replay!(scope_kind, scope_id, event_envelopes, checkpoint_envelope, opts)

    {events, _previous_event_hash} =
      event_envelopes
      |> Enum.with_index(1)
      |> Enum.reduce({[], nil}, fn {envelope, expected_sequence}, {events, previous_event_hash} ->
        payload = Envelope.payload!(envelope, :event)
        signatures = Envelope.signatures!(envelope)

        Assertions.assert_literal!(payload["scope_kind"], scope_kind, "event_scope_kind_mismatch")
        Assertions.assert_literal!(payload["scope_id"], scope_id, "event_scope_id_mismatch")
        Assertions.assert_literal!(payload["sequence"], expected_sequence, "event_sequence_gap")
        Envelope.assert_event_chain_link!(payload, previous_event_hash)
        Signatures.verify_event_signatures!(payload, signatures, checkpoint_envelope)
        event = Store.insert_event!(payload, signatures)

        {[event | events], event.event_hash}
      end)

    events = Enum.reverse(events)
    checkpoint_payload = Envelope.payload!(checkpoint_envelope, :checkpoint)
    checkpoint_signatures = Envelope.signatures!(checkpoint_envelope)
    event_head = Envelope.event_head!(events)

    Assertions.assert_literal!(
      checkpoint_payload["scope_kind"],
      scope_kind,
      "checkpoint_scope_kind_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["scope_id"],
      scope_id,
      "checkpoint_scope_id_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["sequence"],
      1,
      "initial_checkpoint_sequence_invalid"
    )

    Assertions.assert_literal!(
      checkpoint_payload["covered_event_head"],
      event_head,
      "checkpoint_event_head_mismatch"
    )

    State.assert_checkpoint_state_matches_replay!(
      checkpoint_payload,
      Replay.initial_checkpoint_payload!(checkpoint_payload, event_envelopes)
    )

    Signatures.verify_checkpoint_signatures!(
      checkpoint_payload,
      checkpoint_signatures,
      expected_signer_kind
    )

    checkpoint = Store.insert_checkpoint!(checkpoint_payload, checkpoint_signatures)
    pin = Store.initial_checkpoint_pin!(checkpoint)

    %{events: events, checkpoint: checkpoint, pin: pin}
  end

  def append_signed_scope!(
        scope_kind,
        scope_id,
        event_envelopes,
        checkpoint_envelope,
        opts \\ []
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_list(event_envelopes) and
             is_map(checkpoint_envelope) do
    case Repo.transaction(fn ->
           do_append_signed_scope!(
             scope_kind,
             scope_id,
             event_envelopes,
             checkpoint_envelope,
             opts
           )
         end) do
      {:ok, result} -> result
      {:error, reason} -> raise ArgumentError, inspect(reason)
    end
  end

  def append_signed_scope(scope_kind, scope_id, event_envelopes, checkpoint_envelope, opts \\ []) do
    append_signed_scope!(scope_kind, scope_id, event_envelopes, checkpoint_envelope, opts)
    :ok
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  defp do_append_signed_scope!(scope_kind, scope_id, event_envelopes, checkpoint_envelope, opts) do
    expected_signer_kind = Keyword.fetch!(opts, :checkpoint_signer_kind)

    authorized_share_participant_keys =
      Keyword.get(opts, :authorized_share_participant_keys, %{})

    previous_checkpoint = Store.current_checkpoint(scope_kind, scope_id)
    previous_pin = Store.current_pin(scope_kind, scope_id)

    if is_nil(previous_checkpoint) or is_nil(previous_pin),
      do: raise(ArgumentError, "key_directory_checkpoint_required")

    if event_envelopes == [], do: raise(ArgumentError, "key_directory_append_events_required")

    checkpoint_payload = Envelope.payload!(checkpoint_envelope, :checkpoint)
    checkpoint_signatures = Envelope.signatures!(checkpoint_envelope)

    Assertions.assert_literal!(
      checkpoint_payload["scope_kind"],
      scope_kind,
      "checkpoint_scope_kind_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["scope_id"],
      scope_id,
      "checkpoint_scope_id_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["sequence"],
      previous_pin.checkpoint_sequence + 1,
      "checkpoint_sequence_gap"
    )

    Assertions.assert_literal!(
      checkpoint_payload["previous_checkpoint_hash"],
      previous_pin.checkpoint_hash,
      "checkpoint_previous_hash_mismatch"
    )

    initial_authority_state =
      Authority.stored_authority_state(%{
        "scope_kind" => scope_kind,
        "scope_id" => scope_id,
        "sequence" => previous_pin.event_head_sequence + 1
      })

    event_payloads = Enum.map(event_envelopes, &Envelope.payload!(&1, :event))
    next_payloads = Enum.drop(event_payloads, 1) ++ [nil]

    {events, _previous_event_hash, replay_payload, _authority_state} =
      event_envelopes
      |> Enum.zip(next_payloads)
      |> Enum.with_index(previous_pin.event_head_sequence + 1)
      |> Enum.reduce(
        {[], previous_pin.event_head_hash, previous_checkpoint.payload, initial_authority_state},
        fn {{envelope, next_payload}, expected_sequence},
           {events, previous_event_hash, replay_payload, authority_state} ->
          payload = Envelope.payload!(envelope, :event)
          signatures = Envelope.signatures!(envelope)

          Assertions.assert_literal!(
            payload["scope_kind"],
            scope_kind,
            "event_scope_kind_mismatch"
          )

          Assertions.assert_literal!(payload["scope_id"], scope_id, "event_scope_id_mismatch")
          Assertions.assert_literal!(payload["sequence"], expected_sequence, "event_sequence_gap")
          Envelope.assert_event_chain_link!(payload, previous_event_hash)

          admission_wrap? = Signatures.invitation_admission_wrap_event?(payload, next_payload)

          recipient_bound_delivery_wrap? =
            recipient_bound_workspace_delivery_wrap?(payload, event_payloads)

          recipient_bound_wrap? = admission_wrap? or recipient_bound_delivery_wrap?

          authority_state =
            if admission_wrap? do
              authority_state
            else
              Authority.assert_and_apply_event!(authority_state, payload)
            end

          if recipient_bound_wrap? do
            Semantics.assert_invitation_admission_wrap_event_semantics!(
              payload,
              checkpoint_payload
            )
          else
            Replay.assert_event_semantics_against_checkpoint!(payload, checkpoint_payload)
          end

          signature_checkpoint_payload =
            if admission_wrap? do
              checkpoint_payload
            else
              Signatures.event_signature_checkpoint_payload(
                payload,
                signatures,
                replay_payload,
                checkpoint_payload,
                authorized_share_participant_keys
              )
              |> Signatures.invitation_redeem_authority_payload_for_event(
                payload,
                previous_pin.event_head_sequence
              )
            end

          Signatures.verify_event_signatures!(payload, signatures, signature_checkpoint_payload,
            verify_semantics: false,
            semantic_checkpoint_payload: checkpoint_payload,
            allow_inactive_signer: admission_wrap?
          )

          event = Store.insert_event!(payload, signatures)

          next_replay_payload =
            if recipient_bound_wrap? do
              replay_payload
            else
              apply_append_event_to_replay!(
                replay_payload,
                payload,
                signatures,
                checkpoint_payload,
                authorized_share_participant_keys,
                event_payloads
              )
            end

          {[event | events], event.event_hash, next_replay_payload, authority_state}
        end
      )

    events = Enum.reverse(events)

    Assertions.assert_literal!(
      checkpoint_payload["covered_event_head"],
      Envelope.event_head!(events),
      "checkpoint_event_head_mismatch"
    )

    Store.assert_pin_monotonic!(previous_pin, checkpoint_payload)
    State.assert_checkpoint_state_matches_replay!(checkpoint_payload, replay_payload)

    checkpoint_signature_authority_payload =
      Signatures.checkpoint_signature_authority_payload!(
        expected_signer_kind,
        previous_checkpoint.payload,
        checkpoint_payload,
        events,
        previous_pin.event_head_sequence
      )

    Signatures.verify_checkpoint_signatures!(
      checkpoint_payload,
      checkpoint_signatures,
      expected_signer_kind,
      checkpoint_signature_authority_payload,
      previous_checkpoint.payload,
      allowed_inactive_signing_key_ids:
        inactive_checkpoint_signers_allowed_by_append(expected_signer_kind, events)
    )

    checkpoint = Store.insert_checkpoint!(checkpoint_payload, checkpoint_signatures)
    pin = Store.advance_pin!(previous_pin, checkpoint)

    %{events: events, checkpoint: checkpoint, pin: pin}
  end

  defp apply_append_event_to_replay!(
         replay_payload,
         %{"event_type" => "guest_invitation_redeemed"} = payload,
         signatures,
         checkpoint_payload,
         authorized_share_participant_keys,
         event_payloads
       ) do
    if recipient_bound_guest_redeem?(payload, event_payloads) do
      Replay.apply_recipient_bound_guest_invitation_redeemed!(
        replay_payload,
        payload,
        signatures,
        checkpoint_payload
      )
    else
      Replay.apply_event_to_checkpoint_payload!(
        replay_payload,
        payload,
        signatures,
        checkpoint_payload,
        authorized_share_participant_keys
      )
    end
  end

  defp apply_append_event_to_replay!(
         replay_payload,
         %{"event_type" => "workspace_invitation_redeemed"} = payload,
         signatures,
         checkpoint_payload,
         authorized_share_participant_keys,
         event_payloads
       ) do
    if recipient_bound_workspace_redeem?(payload, event_payloads) do
      Replay.apply_recipient_bound_workspace_invitation_redeemed!(
        replay_payload,
        payload,
        signatures,
        checkpoint_payload
      )
    else
      Replay.apply_event_to_checkpoint_payload!(
        replay_payload,
        payload,
        signatures,
        checkpoint_payload,
        authorized_share_participant_keys
      )
    end
  end

  defp apply_append_event_to_replay!(
         replay_payload,
         payload,
         signatures,
         checkpoint_payload,
         authorized_share_participant_keys,
         _event_payloads
       ) do
    Replay.apply_event_to_checkpoint_payload!(
      replay_payload,
      payload,
      signatures,
      checkpoint_payload,
      authorized_share_participant_keys
    )
  end

  defp recipient_bound_guest_redeem?(redeemed, event_payloads) do
    case event_payloads do
      [
        %{"event_type" => "recipient_bound_delivery_admitted", "body" => admission_body},
        ^redeemed
      ] ->
        body = redeemed["body"]

        admission_body["context_kind"] == "guest_invitation" and
          admission_body["context_id"] == body["guest_invitation_id"] and
          admission_body["recipient_device_id"] == body["guest_device_id"] and
          body["recipient_account_user_id"] != body["guest_user_id"] and
          is_binary(body["recipient_account_user_id"]) and
          is_binary(body["recipient_account_device_id"])

      _ ->
        false
    end
  end

  defp recipient_bound_workspace_redeem?(redeemed, event_payloads) do
    event_payloads
    |> Enum.chunk_every(3, 1, :discard)
    |> Enum.any?(&recipient_bound_workspace_redeem_window?(&1, redeemed))
  end

  defp recipient_bound_workspace_delivery_wrap?(delivery, event_payloads) do
    event_payloads
    |> Enum.chunk_every(4, 1, :discard)
    |> Enum.any?(&recipient_bound_workspace_delivery_window?(&1, delivery, event_payloads))
  end

  defp recipient_bound_workspace_redeem_window?(
         [
           %{"event_type" => "recipient_bound_delivery_admitted", "body" => admission_body},
           %{"event_type" => "wrap_issued", "body" => wrap_body},
           redeemed
         ],
         redeemed
       ) do
    redeemed_body = redeemed["body"]

    workspace_redeem_admission_matches?(admission_body, redeemed_body) and
      workspace_member_wrap_matches?(wrap_body, redeemed)
  end

  defp recipient_bound_workspace_redeem_window?(_, _), do: false

  defp workspace_redeem_admission_matches?(admission_body, redeemed_body) do
    admission_body["context_kind"] == "workspace_invitation" and
      admission_body["context_id"] == redeemed_body["invitation_id"] and
      admission_body["recipient_device_id"] == redeemed_body["redeemed_device_id"]
  end

  defp workspace_member_wrap_matches?(wrap_body, redeemed) do
    redeemed_body = redeemed["body"]
    sender = wrap_body["sender"]
    recipient = wrap_body["recipient"]
    resource = wrap_body["resource"]
    actor = redeemed["actor"]

    fields_match?([
      {wrap_body["purpose"], "workspace_member_kek_wrap"},
      {resource["workspace_id"], redeemed["scope_id"]},
      {resource["target_user_id"], redeemed_body["redeemed_user_id"]},
      {recipient["recipient_kind"], "user_identity"},
      {recipient["user_id"], redeemed_body["redeemed_user_id"]},
      {recipient["key_scope_kind"], "user"},
      {recipient["key_scope_id"], redeemed_body["redeemed_user_id"]},
      {sender["user_id"], actor["user_id"]},
      {sender["device_id"], actor["device_id"]},
      {sender["signing_key_id"], actor["signing_key_id"]}
    ])
  end

  defp recipient_bound_workspace_delivery_window?(
         [
           %{"event_type" => "recipient_bound_delivery_admitted"},
           %{"event_type" => "wrap_issued"},
           %{"event_type" => "workspace_invitation_redeemed"} = redeemed,
           delivery
         ],
         delivery,
         event_payloads
       ) do
    recipient_bound_workspace_redeem?(redeemed, event_payloads) and
      workspace_delivery_wrap_matches?(delivery, redeemed)
  end

  defp recipient_bound_workspace_delivery_window?(_, _, _), do: false

  defp workspace_delivery_wrap_matches?(delivery, redeemed) do
    body = delivery["body"]
    recipient = body["recipient"]
    resource = body["resource"]
    redeemed_body = redeemed["body"]

    fields_match?([
      {delivery["event_type"], "wrap_issued"},
      {body["purpose"], "workspace_invitation_kek_wrap"},
      {resource["invitation_id"], redeemed_body["invitation_id"]},
      {resource["redeemed_user_id"], redeemed_body["redeemed_user_id"]},
      {resource["redeemed_device_id"], redeemed_body["redeemed_device_id"]},
      {recipient["recipient_kind"], "invitee"},
      {recipient["invitee_user_id"], redeemed_body["redeemed_user_id"]},
      {recipient["invitee_device_id"], redeemed_body["redeemed_device_id"]},
      {recipient["key_scope_kind"], "user"},
      {recipient["key_scope_id"], redeemed_body["redeemed_user_id"]}
    ])
  end

  defp fields_match?(pairs), do: Enum.all?(pairs, fn {actual, expected} -> actual == expected end)

  defp inactive_checkpoint_signers_allowed_by_append(
         "device",
         [
           %Event{
             payload: %{
               "event_type" => "member_removed",
               "actor" => %{
                 "signer_kind" => "device",
                 "user_id" => user_id,
                 "signing_key_id" => signing_key_id
               },
               "body" => %{"user_id" => user_id}
             }
           }
           | revocation_events
         ]
       )
       when is_binary(signing_key_id) do
    if member_removal_revocations_authorize_signer?(revocation_events, signing_key_id) do
      [signing_key_id]
    else
      []
    end
  end

  defp inactive_checkpoint_signers_allowed_by_append(_expected_signer_kind, _events), do: []

  defp member_removal_key_revocation?(%Event{
         payload: %{
           "event_type" => event_type,
           "body" => %{"key_id" => key_id, "reason" => "member_removed"}
         }
       })
       when event_type in ["signing_key_revoked", "encryption_key_revoked"] and is_binary(key_id),
       do: true

  defp member_removal_key_revocation?(_event), do: false

  defp member_removal_revocations_authorize_signer?(revocation_events, signing_key_id) do
    revocation_events
    |> Enum.reduce_while(false, fn event, signing_key_revoked? ->
      if member_removal_key_revocation?(event) do
        {:cont,
         signing_key_revoked? or member_removal_signing_key_revocation?(event, signing_key_id)}
      else
        {:halt, false}
      end
    end)
  end

  defp member_removal_signing_key_revocation?(
         %Event{
           payload: %{
             "event_type" => "signing_key_revoked",
             "body" => %{"key_id" => key_id, "reason" => "member_removed"}
           }
         },
         key_id
       ),
       do: true

  defp member_removal_signing_key_revocation?(_event, _signing_key_id), do: false

  def verify_complete_replay!(
        scope_kind,
        scope_id,
        event_envelopes,
        checkpoint_envelope,
        opts \\ []
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_list(event_envelopes) and
             is_map(checkpoint_envelope) do
    expected_signer_kind = Keyword.fetch!(opts, :checkpoint_signer_kind)

    checkpoint_payload = Envelope.payload!(checkpoint_envelope, :checkpoint)

    initial_replay_payload =
      checkpoint_payload
      |> Map.put("identity_keys", [])
      |> Map.put("device_keys", [])
      |> Map.put("share_participant_keys", [])
      |> Map.put("revoked_key_ids", [])

    authorized_share_participant_keys = State.share_participant_entries_by_id(checkpoint_payload)

    {verified_events, _previous_hash, _authority_state, replay_payload} =
      event_envelopes
      |> Enum.with_index(1)
      |> Enum.reduce(
        {[], nil, Authority.empty_state(), initial_replay_payload},
        fn {envelope, expected_sequence},
           {events, previous_event_hash, authority_state, replay_payload} ->
          payload = Envelope.payload!(envelope, :event)
          signatures = Envelope.signatures!(envelope)

          Assertions.assert_literal!(
            payload["scope_kind"],
            scope_kind,
            "event_scope_kind_mismatch"
          )

          Assertions.assert_literal!(payload["scope_id"], scope_id, "event_scope_id_mismatch")
          Assertions.assert_literal!(payload["sequence"], expected_sequence, "event_sequence_gap")
          Envelope.assert_event_chain_link!(payload, previous_event_hash)

          Replay.assert_event_semantics_against_checkpoint!(
            payload,
            checkpoint_payload
          )

          authority_state = Authority.assert_and_apply_event!(authority_state, payload)

          signature_replay_payload =
            event_signature_replay_payload!(
              replay_payload,
              payload,
              signatures,
              checkpoint_payload,
              authorized_share_participant_keys
            )

          Signatures.verify_event_signatures!(payload, signatures, signature_replay_payload,
            verify_semantics: false,
            semantic_checkpoint_payload: checkpoint_payload
          )

          replay_payload =
            Replay.apply_event_to_checkpoint_payload!(
              replay_payload,
              payload,
              signatures,
              checkpoint_payload,
              authorized_share_participant_keys
            )

          event_hash = event_hash(payload)

          {[%{payload: payload, event_hash: event_hash, sequence: payload["sequence"]} | events],
           event_hash, authority_state, replay_payload}
        end
      )

    verified_events = Enum.reverse(verified_events)
    checkpoint_signatures = Envelope.signatures!(checkpoint_envelope)
    event_head = Envelope.verified_event_head!(verified_events)

    Assertions.assert_literal!(
      checkpoint_payload["scope_kind"],
      scope_kind,
      "checkpoint_scope_kind_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["scope_id"],
      scope_id,
      "checkpoint_scope_id_mismatch"
    )

    Assertions.assert_literal!(
      checkpoint_payload["covered_event_head"],
      event_head,
      "checkpoint_event_head_mismatch"
    )

    State.assert_checkpoint_state_matches_replay!(
      checkpoint_payload,
      replay_payload
    )

    Signatures.verify_checkpoint_signatures!(
      checkpoint_payload,
      checkpoint_signatures,
      expected_signer_kind
    )

    :ok
  end

  defp event_signature_replay_payload!(
         replay_payload,
         %{"event_type" => "identity_key_added"} = payload,
         _signatures,
         checkpoint_payload,
         _authorized_share_participant_keys
       ) do
    State.update_key_entries!(
      replay_payload,
      "identity_keys",
      State.key_entry_by_id!(checkpoint_payload, payload["body"]["key_id"])
    )
  end

  defp event_signature_replay_payload!(
         replay_payload,
         %{"event_type" => "device_key_added"} = payload,
         _signatures,
         checkpoint_payload,
         _authorized_share_participant_keys
       ) do
    replay_payload
    |> State.update_key_entries!(
      "device_keys",
      State.key_entry_by_id!(checkpoint_payload, payload["body"]["signing_key_id"])
    )
    |> State.update_key_entries!(
      "device_keys",
      State.key_entry_by_id!(checkpoint_payload, payload["body"]["encryption_key_id"])
    )
  end

  defp event_signature_replay_payload!(
         replay_payload,
         payload,
         signatures,
         checkpoint_payload,
         authorized_share_participant_keys
       ) do
    Signatures.event_signature_checkpoint_payload(
      payload,
      signatures,
      replay_payload,
      checkpoint_payload,
      authorized_share_participant_keys
    )
  end

  @doc "Key-directory package boundary for current checkpoint lookup."
  def current_checkpoint(scope_kind, scope_id), do: Store.current_checkpoint(scope_kind, scope_id)

  @doc "Key-directory package boundary for current pin lookup."
  def current_pin(scope_kind, scope_id), do: Store.current_pin(scope_kind, scope_id)

  @doc "Key-directory package boundary for stored checkpoint assertions."
  def assert_stored_checkpoint!(checkpoint), do: Store.assert_stored_checkpoint!(checkpoint)

  @doc "Key-directory package boundary for stored event assertions."
  def assert_stored_event!(event), do: Store.assert_stored_event!(event)

  @doc "Key-directory package boundary for active key lookup at the current checkpoint."
  def active_key_material_in_current_checkpoint(scope_kind, scope_id, key_id),
    do: Store.active_key_material_in_current_checkpoint(scope_kind, scope_id, key_id)

  @doc "Key-directory package boundary for active owner signing material lookup."
  def active_owner_signing_material_in_current_checkpoint(
        scope_kind,
        scope_id,
        owner_kind,
        owner_id
      ),
      do:
        Store.active_owner_signing_material_in_current_checkpoint(
          scope_kind,
          scope_id,
          owner_kind,
          owner_id
        )

  @doc "Key-directory package boundary for active owner encryption material lookup."
  def active_owner_encryption_material_in_current_checkpoint(
        scope_kind,
        scope_id,
        owner_kind,
        owner_id
      ),
      do:
        Store.active_owner_encryption_material_in_current_checkpoint(
          scope_kind,
          scope_id,
          owner_kind,
          owner_id
        )

  @doc "Key-directory package boundary for historical key material lookup at a checkpoint."
  def active_key_material_at_checkpoint(
        scope_kind,
        scope_id,
        key_id,
        checkpoint_sequence,
        checkpoint_hash
      ),
      do:
        Store.active_key_material_at_checkpoint(
          scope_kind,
          scope_id,
          key_id,
          checkpoint_sequence,
          checkpoint_hash
        )

  @doc "Key-directory package boundary for ordered event history lookup."
  def events_up_to(scope_kind, scope_id, head_sequence),
    do: Store.events_up_to(scope_kind, scope_id, head_sequence)

  @doc "Key-directory package boundary for ordered event range lookup."
  def events_after_until(scope_kind, scope_id, after_sequence, head_sequence),
    do: Store.events_after_until(scope_kind, scope_id, after_sequence, head_sequence)

  @doc "Returns signed lifecycle events needed to verify transitions after an anchor."
  def authority_events(
        scope_kind,
        scope_id,
        anchor_event_sequence,
        candidate_events,
        candidate_checkpoint
      )
      when is_integer(anchor_event_sequence) and is_list(candidate_events) do
    rotation_keys =
      candidate_events
      |> Enum.filter(&(&1.event_type in ["rotation_completed", "old_key_deleted"]))
      |> Enum.map(&rotation_key/1)
      |> MapSet.new()

    invitation_ids = invitation_authority_ids(candidate_events, candidate_checkpoint)

    scope_kind
    |> events_up_to(scope_id, anchor_event_sequence)
    |> Enum.filter(fn event ->
      rotation_authority_event?(event, rotation_keys) or
        invitation_authority_event?(event, invitation_ids)
    end)
  end

  defp rotation_authority_event?(event, rotation_keys) do
    MapSet.size(rotation_keys) > 0 and
      event.event_type in ["rotation_started", "rotation_completed"] and
      MapSet.member?(rotation_keys, rotation_key(event))
  end

  defp invitation_authority_ids(candidate_events, candidate_checkpoint) do
    event_ids =
      candidate_events
      |> Enum.flat_map(&invitation_id/1)
      |> MapSet.new()

    candidate_checkpoint
    |> Map.get(:signatures, [])
    |> Enum.reduce(event_ids, fn
      %{
        "signer" => %{
          "signer_kind" => "invitation_redeem_authority",
          "invitation_id" => invitation_id
        }
      },
      ids
      when is_binary(invitation_id) ->
        MapSet.put(ids, invitation_id)

      _, ids ->
        ids
    end)
  end

  defp invitation_id(event) do
    body = event.payload["body"]

    case event.event_type do
      "workspace_invitation_redeemed" -> [body["invitation_id"]]
      "guest_invitation_redeemed" -> [body["guest_invitation_id"]]
      _ -> []
    end
  end

  defp invitation_authority_event?(event, invitation_ids) do
    body = event.payload["body"]

    case event.event_type do
      event_type
      when event_type in [
             "workspace_invitation_created",
             "workspace_invitation_revoked",
             "workspace_invitation_redeemed"
           ] ->
        MapSet.member?(invitation_ids, body["invitation_id"])

      event_type
      when event_type in [
             "guest_invitation_created",
             "guest_invitation_revoked",
             "guest_invitation_redeemed"
           ] ->
        MapSet.member?(invitation_ids, body["guest_invitation_id"])

      _ ->
        false
    end
  end

  defp rotation_key(event) do
    body = event.payload["body"]

    {
      body["rotation_kind"],
      body["scope_kind"],
      body["scope_id"],
      if(body["rotation_kind"] == "identity",
        do: body["old_identity_signing_key_id"],
        else: body["old_key_version"]
      )
    }
  end

  @doc "Key-directory package boundary for ordered checkpoint range lookup."
  def checkpoints_between(scope_kind, scope_id, start_sequence, end_sequence),
    do: Store.checkpoints_between(scope_kind, scope_id, start_sequence, end_sequence)

  def event_by_body_field(scope_kind, scope_id, event_type, body_key, body_value) do
    Repo.one(
      from(e in Event,
        where:
          e.scope_kind == ^scope_kind and e.scope_id == ^scope_id and
            e.event_type == ^event_type and
            fragment("?->'body'->>? = ?", e.payload, ^body_key, ^body_value),
        order_by: [desc: e.sequence],
        limit: 1
      )
    )
  end

  def event_by_hash(scope_kind, scope_id, event_hash) do
    Repo.one(
      from(e in Event,
        where:
          e.scope_kind == ^scope_kind and e.scope_id == ^scope_id and
            e.event_hash == ^event_hash,
        limit: 1
      )
    )
  end

  def checkpoint_covering_event_head(scope_kind, scope_id, event_head_sequence) do
    Repo.one(
      from(c in Checkpoint,
        where:
          c.scope_kind == ^scope_kind and c.scope_id == ^scope_id and
            c.covered_event_head_sequence == ^event_head_sequence,
        order_by: [desc: c.sequence],
        limit: 1
      )
    )
  end
end
