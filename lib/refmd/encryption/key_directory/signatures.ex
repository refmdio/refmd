defmodule RefMD.Encryption.KeyDirectory.Signatures do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Signature

  alias RefMD.Encryption.KeyDirectory.{
    Assertions,
    Envelope,
    Event,
    Payload,
    Replay,
    SignatureEnvelope
  }

  alias RefMD.Encryption.KeyDirectory.State, as: State
  alias RefMD.Repo

  @spec verify_event_signatures!(map(), [map()], map(), keyword()) :: :ok
  def verify_event_signatures!(payload, signatures, checkpoint_authority, opts \\ []) do
    checkpoint_payload =
      case checkpoint_authority do
        %{"payload" => _} -> Envelope.payload!(checkpoint_authority, :checkpoint)
        %{} -> checkpoint_authority
      end

    semantic_checkpoint_payload =
      Keyword.get(opts, :semantic_checkpoint_payload, checkpoint_payload)

    signing_keys = signing_key_material_by_id!(checkpoint_payload)

    if Keyword.get(opts, :verify_semantics, true) do
      Replay.assert_event_semantics_against_checkpoint!(payload, semantic_checkpoint_payload)
    end

    Enum.each(signatures, fn signature_envelope ->
      {signer, signature} = SignatureEnvelope.parts!(signature_envelope)
      public_material = signing_key_material!(signing_keys, signer["signing_key_id"], :event)
      assert_signer_matches_material!(signer, public_material)
      assert_event_actor_matches_signer!(payload, signer)

      unless Keyword.get(opts, :allow_inactive_signer, false) do
        State.assert_key_entry_active_at_sequence!(
          checkpoint_payload,
          signer["signing_key_id"],
          payload["sequence"]
        )
      end

      transcript =
        Signature.build_key_directory_event_transcript!(
          payload["event_type"],
          public_material["owner_kind"],
          public_material["owner_id"],
          payload
        )

      case Signature.verify_hybrid_signature_result(
             "key_directory_event",
             transcript,
             signature,
             public_material,
             %{
               event_payload: payload,
               checkpoint_payload: semantic_checkpoint_payload,
               event_semantics_verified: not Keyword.get(opts, :verify_semantics, true)
             }
           ) do
        :ok ->
          :ok

        {:error, :invalid_signature} ->
          raise ArgumentError, "key_directory_event_signature_invalid"

        {:error, reason} ->
          raise ArgumentError, Atom.to_string(reason)
      end
    end)
  end

  @spec invitation_admission_wrap_event?(map(), map() | nil) :: boolean()
  def invitation_admission_wrap_event?(
        %{
          "event_type" => "wrap_issued",
          "body" => %{
            "purpose" => "workspace_member_kek_wrap",
            "sender" => sender,
            "recipient" => recipient
          }
        },
        %{
          "event_type" => "workspace_invitation_redeemed",
          "body" => next_body
        }
      )
      when is_map(sender) and is_map(recipient) and is_map(next_body) do
    recipient["user_id"] == next_body["redeemed_user_id"] and
      sender["user_id"] == next_body["redeemed_user_id"] and
      sender["device_id"] == next_body["redeemed_device_id"]
  end

  def invitation_admission_wrap_event?(_, _), do: false

  @spec verify_checkpoint_signatures!(map(), [map()], String.t()) :: :ok
  def verify_checkpoint_signatures!(payload, signatures, expected_signer_kind) do
    verify_checkpoint_signatures!(payload, signatures, expected_signer_kind, payload)
  end

  @spec checkpoint_signature_authority_payload!(
          String.t(),
          map(),
          map(),
          [Event.t()],
          pos_integer()
        ) ::
          map()
  def checkpoint_signature_authority_payload!(
        "share_participant_device",
        _previous_payload,
        checkpoint_payload,
        _events,
        _previous_head_sequence
      ),
      do: checkpoint_payload

  def checkpoint_signature_authority_payload!(
        "invitation_redeem_authority",
        previous_payload,
        _checkpoint_payload,
        events,
        previous_head_sequence
      ) do
    case invitation_redeem_payload_from_events(events) do
      %{} = payload ->
        invitation_redeem_authority_payload_for_event(
          previous_payload,
          payload,
          previous_head_sequence
        )

      nil ->
        raise(ArgumentError, "invitation_redeem_authority_event_missing")
    end
  end

  def checkpoint_signature_authority_payload!(
        _expected_signer_kind,
        previous_payload,
        _checkpoint_payload,
        _events,
        _previous_head_sequence
      ),
      do: previous_payload

  @spec invitation_redeem_authority_payload_for_event(map(), map(), pos_integer()) :: map()
  def invitation_redeem_authority_payload_for_event(
        checkpoint_payload,
        %{"event_type" => event_type} = payload,
        previous_head_sequence
      )
      when event_type in ["workspace_invitation_redeemed", "guest_invitation_redeemed"] do
    entry = invitation_redeem_authority_entry!(payload, previous_head_sequence)

    Map.update(checkpoint_payload, "temporary_authority_keys", [entry], fn entries ->
      entries ++ [entry]
    end)
  end

  def invitation_redeem_authority_payload_for_event(checkpoint_payload, _payload, _sequence),
    do: checkpoint_payload

  @spec invitation_redeem_payload_from_events([Event.t()]) :: map() | nil
  def invitation_redeem_payload_from_events(events) when is_list(events) do
    Enum.find_value(events, fn
      %Event{payload: %{"event_type" => event_type} = payload}
      when event_type in ["workspace_invitation_redeemed", "guest_invitation_redeemed"] ->
        payload

      _ ->
        nil
    end)
  end

  @spec invitation_redeem_authority_entry!(map(), pos_integer()) :: map()
  def invitation_redeem_authority_entry!(payload, previous_head_sequence) do
    created_event = invitation_redeem_created_event!(payload, previous_head_sequence)
    authority = created_event.payload["body"]["redeem_authority"]
    key_material = authority["hybrid_signing_public_key_material"]
    invitation_id = invitation_redeem_invitation_id!(payload)

    Assertions.assert_literal!(
      Payload.key_id!(key_material),
      authority["signing_key_id"],
      "invitation_redeem_authority_key_mismatch"
    )

    Assertions.assert_literal!(
      key_material["owner_kind"],
      "invitation_redeem_authority",
      "invitation_redeem_authority_owner_kind_invalid"
    )

    Assertions.assert_literal!(
      key_material["owner_id"],
      invitation_id,
      "invitation_redeem_authority_owner_id_mismatch"
    )

    %{
      "key_id" => authority["signing_key_id"],
      "key_material" => key_material,
      "valid_from" => State.event_ref!(created_event.payload)
    }
  end

  @spec invitation_redeem_created_event!(map(), pos_integer()) :: Event.t()
  def invitation_redeem_created_event!(
        %{
          "event_type" => "workspace_invitation_redeemed",
          "scope_kind" => scope_kind,
          "scope_id" => scope_id,
          "body" => %{"invitation_id" => invitation_id}
        } = payload,
        previous_head_sequence
      ) do
    created_event =
      find_invitation_created_event!(
        scope_kind,
        scope_id,
        "workspace_invitation_created",
        "invitation_id",
        invitation_id,
        previous_head_sequence
      )

    assert_invitation_redeem_authority_active!(created_event, payload, previous_head_sequence)
    created_event
  end

  def invitation_redeem_created_event!(
        %{
          "event_type" => "guest_invitation_redeemed",
          "scope_kind" => scope_kind,
          "scope_id" => scope_id,
          "body" => %{"guest_invitation_id" => invitation_id}
        } = payload,
        previous_head_sequence
      ) do
    created_event =
      find_invitation_created_event!(
        scope_kind,
        scope_id,
        "guest_invitation_created",
        "guest_invitation_id",
        invitation_id,
        previous_head_sequence
      )

    assert_invitation_redeem_authority_active!(created_event, payload, previous_head_sequence)
    created_event
  end

  defp assert_invitation_redeem_authority_active!(
         %Event{} = created_event,
         %{"event_type" => redeem_event_type, "sequence" => redeem_sequence} = redeem_payload,
         previous_head_sequence
       ) do
    {invitation_id_field, revoked_event_type} = redeem_lifecycle_fields!(redeem_event_type)

    invitation_id = invitation_redeem_invitation_id!(redeem_payload)
    assert_redeem_not_expired!(created_event, redeem_sequence)

    Event
    |> where(
      [e],
      e.scope_kind == ^created_event.scope_kind and e.scope_id == ^created_event.scope_id and
        e.sequence > ^created_event.sequence and e.sequence <= ^previous_head_sequence and
        e.event_type in [^revoked_event_type, ^redeem_event_type]
    )
    |> Repo.all()
    |> Enum.any?(fn event ->
      get_in(event.payload, ["body", invitation_id_field]) == invitation_id
    end)
    |> if(do: raise(ArgumentError, "invitation_redeem_authority_inactive"), else: :ok)
  end

  defp redeem_lifecycle_fields!("workspace_invitation_redeemed"),
    do: {"invitation_id", "workspace_invitation_revoked"}

  defp redeem_lifecycle_fields!("guest_invitation_redeemed"),
    do: {"guest_invitation_id", "guest_invitation_revoked"}

  defp assert_redeem_not_expired!(%Event{} = created_event, redeem_sequence) do
    expires_event_sequence = get_in(created_event.payload, ["body", "expires_event_sequence"])

    if is_integer(expires_event_sequence) and redeem_sequence >= expires_event_sequence do
      raise ArgumentError, "invitation_redeem_authority_expired"
    end
  end

  @spec find_invitation_created_event!(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          pos_integer()
        ) :: Event.t()
  def find_invitation_created_event!(
        scope_kind,
        scope_id,
        event_type,
        invitation_id_field,
        invitation_id,
        previous_head_sequence
      ) do
    Event
    |> where(
      [e],
      e.scope_kind == ^scope_kind and e.scope_id == ^scope_id and e.event_type == ^event_type and
        e.sequence <= ^previous_head_sequence
    )
    |> order_by([e], desc: e.sequence)
    |> Repo.all()
    |> Enum.find(fn event ->
      get_in(event.payload, ["body", invitation_id_field]) == invitation_id
    end)
    |> case do
      %Event{} = event -> event
      nil -> raise(ArgumentError, "invitation_redeem_authority_created_event_missing")
    end
  end

  @spec invitation_redeem_invitation_id!(map()) :: String.t()
  def invitation_redeem_invitation_id!(%{
        "event_type" => "workspace_invitation_redeemed",
        "body" => %{"invitation_id" => invitation_id}
      }),
      do: invitation_id

  def invitation_redeem_invitation_id!(%{
        "event_type" => "guest_invitation_redeemed",
        "body" => %{"guest_invitation_id" => invitation_id}
      }),
      do: invitation_id

  @spec verify_checkpoint_signatures!(map(), [map()], String.t(), map()) :: :ok
  def verify_checkpoint_signatures!(
        payload,
        signatures,
        expected_signer_kind,
        authority_payload
      ) do
    verify_checkpoint_signatures!(
      payload,
      signatures,
      expected_signer_kind,
      authority_payload,
      nil
    )
  end

  @spec verify_checkpoint_signatures!(map(), [map()], String.t(), map(), map() | nil) :: :ok
  def verify_checkpoint_signatures!(
        payload,
        signatures,
        expected_signer_kind,
        authority_payload,
        previous_payload
      ) do
    verify_checkpoint_signatures!(
      payload,
      signatures,
      expected_signer_kind,
      authority_payload,
      previous_payload,
      []
    )
  end

  @spec verify_checkpoint_signatures!(map(), [map()], String.t(), map(), map() | nil, keyword()) ::
          :ok
  def verify_checkpoint_signatures!(
        payload,
        signatures,
        expected_signer_kind,
        authority_payload,
        previous_payload,
        opts
      ) do
    signing_keys = signing_key_material_by_id!(authority_payload)
    checkpoint_signing_keys = signing_key_material_by_id!(payload)

    allowed_inactive_signing_key_ids =
      opts |> Keyword.get(:allowed_inactive_signing_key_ids, []) |> MapSet.new()

    required_signature_results =
      Enum.map(signatures, fn signature_envelope ->
        {signer, signature} = SignatureEnvelope.parts!(signature_envelope)

        public_material =
          signing_key_material_for_checkpoint!(
            signing_keys,
            checkpoint_signing_keys,
            signer,
            previous_payload,
            payload
          )

        assert_signer_matches_material!(signer, public_material)

        active_payload =
          if signer["signer_kind"] == "invitation_redeem_authority",
            do: authority_payload,
            else: payload

        active_head = active_payload["covered_event_head"]

        if MapSet.member?(allowed_inactive_signing_key_ids, signer["signing_key_id"]) do
          authority_head = authority_payload["covered_event_head"]

          State.assert_key_entry_active_at_sequence!(
            authority_payload,
            signer["signing_key_id"],
            authority_head["head_sequence"]
          )
        else
          State.assert_key_entry_active_at_sequence!(
            active_payload,
            signer["signing_key_id"],
            active_head["head_sequence"]
          )
        end

        variant = checkpoint_signature_variant!(payload, signer, previous_payload)

        valid? =
          Signature.verify_hybrid_signature(
            "key_directory_checkpoint",
            Signature.build_key_directory_checkpoint_transcript!(
              variant,
              public_material["owner_kind"],
              public_material["owner_id"],
              payload,
              signer
            ),
            signature,
            public_material,
            %{checkpoint_payload: payload}
          )

        unless valid?, do: raise(ArgumentError, "key_directory_checkpoint_signature_invalid")

        if signer["signer_kind"] == expected_signer_kind, do: signer["signing_key_id"], else: nil
      end)

    required_signature_key_ids =
      required_signature_results
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    required_signature_count = required_checkpoint_signature_count(payload, expected_signer_kind)

    unless length(required_signature_key_ids) >= required_signature_count,
      do: raise(ArgumentError, "key_directory_checkpoint_required_signature_missing")

    :ok
  end

  @spec signing_key_material!(map(), String.t(), :event | :checkpoint) :: map()
  def signing_key_material!(signing_keys, signing_key_id, :event) do
    Map.get(signing_keys, signing_key_id) ||
      raise(ArgumentError, "key_directory_event_signer_unknown")
  end

  def signing_key_material!(signing_keys, signing_key_id, :checkpoint) do
    Map.get(signing_keys, signing_key_id) ||
      raise(ArgumentError, "key_directory_checkpoint_signer_unknown")
  end

  @spec signing_key_material_for_checkpoint!(map(), map(), map(), map() | nil, map()) :: map()
  def signing_key_material_for_checkpoint!(
        signing_keys,
        checkpoint_signing_keys,
        %{"signing_key_id" => signing_key_id} = signer,
        previous_payload,
        checkpoint_payload
      ) do
    Map.get(signing_keys, signing_key_id) ||
      if device_authorized_checkpoint_signer?(previous_payload, checkpoint_payload, signer) do
        Map.get(checkpoint_signing_keys, signing_key_id)
      end ||
      raise(ArgumentError, "key_directory_checkpoint_signer_unknown")
  end

  @spec checkpoint_signature_variant!(map(), map()) :: String.t()
  def checkpoint_signature_variant!(payload, signer),
    do: checkpoint_signature_variant!(payload, signer, nil)

  @spec checkpoint_signature_variant!(map(), map(), map() | nil) :: String.t()
  def checkpoint_signature_variant!(
        %{"scope_kind" => "user", "sequence" => 1},
        %{
          "signer_kind" => "identity"
        },
        _previous_payload
      ),
      do: "identity_initial"

  def checkpoint_signature_variant!(
        %{"scope_kind" => "user"} = payload,
        %{
          "signer_kind" => "identity"
        },
        _previous_payload
      ) do
    if identity_rotation_checkpoint?(payload), do: "identity_rotation", else: "identity_active"
  end

  def checkpoint_signature_variant!(
        %{"scope_kind" => "workspace", "sequence" => 1},
        %{
          "signer_kind" => "device"
        },
        _previous_payload
      ),
      do: "workspace_initial"

  def checkpoint_signature_variant!(
        %{"scope_kind" => "workspace"} = payload,
        %{"signer_kind" => "device"} = signer,
        previous_payload
      ) do
    if device_authorized_checkpoint_signer?(previous_payload, payload, signer) do
      "device_authorized"
    else
      "workspace_authorized"
    end
  end

  def checkpoint_signature_variant!(
        %{"scope_kind" => "workspace"},
        %{"signer_kind" => "share_participant_device"},
        _previous_payload
      ),
      do: "share_participant_document_operation"

  def checkpoint_signature_variant!(
        %{"scope_kind" => "workspace"},
        %{"signer_kind" => "invitation_redeem_authority"},
        _previous_payload
      ),
      do: "invitation_redeem_authority"

  def checkpoint_signature_variant!(_, _, _),
    do: raise(ArgumentError, "checkpoint_signer_kind_invalid")

  defp device_authorized_checkpoint_signer?(
         previous_payload,
         %{"scope_kind" => "workspace"} = checkpoint_payload,
         %{"signer_kind" => "device", "signing_key_id" => signing_key_id}
       )
       when is_map(previous_payload) and is_binary(signing_key_id) do
    not key_entry_present?(previous_payload["device_keys"], signing_key_id) and
      key_entry_present?(checkpoint_payload["device_keys"], signing_key_id)
  end

  defp device_authorized_checkpoint_signer?(_, _, _), do: false

  defp key_entry_present?(entries, key_id) when is_list(entries) do
    Enum.any?(entries, fn
      %{"key_id" => ^key_id} = entry -> not Map.has_key?(entry, "revoked_at")
      _ -> false
    end)
  end

  defp key_entry_present?(_, _), do: false

  defp required_checkpoint_signature_count(%{"scope_kind" => "user"} = payload, "identity") do
    if identity_rotation_checkpoint?(payload), do: 2, else: 1
  end

  defp required_checkpoint_signature_count(_payload, _expected_signer_kind), do: 1

  defp identity_rotation_checkpoint?(%{"sequence" => 1}), do: false

  defp identity_rotation_checkpoint?(%{"scope_kind" => "user", "identity_keys" => entries})
       when is_list(entries) do
    entries
    |> Enum.count(fn entry ->
      is_map(entry) and get_in(entry, ["key_material", "owner_kind"]) == "identity" and
        get_in(entry, ["key_material", "protocol"]) == "refmd.hybrid-signing-key-material" and
        not Map.has_key?(entry, "revoked_at")
    end)
    |> Kernel.>=(2)
  end

  defp identity_rotation_checkpoint?(_payload), do: false

  @spec signing_key_material_by_id!(map()) :: map()
  def signing_key_material_by_id!(checkpoint_payload) do
    State.key_directory_authority_entries(checkpoint_payload)
    |> Enum.map(fn %{"key_id" => key_id, "key_material" => material} ->
      if material["protocol"] == "refmd.hybrid-signing-key-material" do
        {key_id, material}
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Map.new()
  end

  @spec assert_event_actor_matches_signer!(map(), map()) :: :ok
  def assert_event_actor_matches_signer!(
        %{
          "actor" => actor,
          "scope_kind" => scope_kind,
          "scope_id" => scope_id,
          "sequence" => sequence
        },
        signer
      )
      when is_map(actor) and is_map(signer) do
    assert_event_actor_signer_common_keys!(actor, signer)
    assert_event_actor_authority!(actor, signer, scope_kind, scope_id, sequence)

    :ok
  end

  def assert_event_actor_matches_signer!(_, _),
    do: raise(ArgumentError, "event_actor_signer_mismatch")

  defp assert_event_actor_signer_common_keys!(actor, signer) do
    Enum.each(
      [
        "signer_kind",
        "share_id",
        "share_participant_principal_id",
        "share_participant_device_id",
        "user_id",
        "principal_id",
        "device_id",
        "invitation_id",
        "signing_key_id",
        "key_scope_kind",
        "key_scope_id",
        "key_checkpoint_sequence",
        "key_checkpoint_hash"
      ],
      fn key ->
        if Map.has_key?(actor, key) or Map.has_key?(signer, key) do
          Assertions.assert_literal!(actor[key], signer[key], "event_actor_signer_mismatch")
        end
      end
    )
  end

  defp assert_event_actor_authority!(_actor, _signer, _scope_kind, _scope_id, sequence)
       when sequence == 1,
       do: :ok

  defp assert_event_actor_authority!(
         %{"signer_kind" => "invitation_redeem_authority"},
         %{"signer_kind" => "invitation_redeem_authority"},
         _scope_kind,
         _scope_id,
         _sequence
       ),
       do: :ok

  defp assert_event_actor_authority!(actor, signer, scope_kind, scope_id, _sequence) do
    Enum.each(
      ["key_scope_kind", "key_scope_id", "key_checkpoint_sequence", "key_checkpoint_hash"],
      fn key ->
        unless Map.has_key?(actor, key) and Map.has_key?(signer, key) do
          raise ArgumentError, "event_actor_signer_authority_missing"
        end
      end
    )

    Assertions.assert_literal!(actor["key_scope_kind"], scope_kind, "event_actor_scope_mismatch")
    Assertions.assert_literal!(actor["key_scope_id"], scope_id, "event_actor_scope_mismatch")
  end

  @spec assert_signer_matches_material!(map(), map()) :: :ok
  def assert_signer_matches_material!(%{"signer_kind" => signer_kind} = signer, material) do
    Assertions.assert_literal!(
      material["owner_kind"],
      signer_owner_kind!(signer_kind),
      "signer_owner_kind_mismatch"
    )

    assert_signer_owner_id_matches_material!(signer_kind, signer, material)
  end

  @spec signer_owner_kind!(String.t()) :: String.t()
  def signer_owner_kind!("identity"), do: "identity"
  def signer_owner_kind!("device"), do: "device"
  def signer_owner_kind!("share_participant_device"), do: "share_participant_device"
  def signer_owner_kind!("invitation_redeem_authority"), do: "invitation_redeem_authority"
  def signer_owner_kind!(_), do: raise(ArgumentError, "signer_kind_invalid")

  @spec assert_signer_owner_id_matches_material!(String.t(), map(), map()) :: :ok
  def assert_signer_owner_id_matches_material!(signer_kind, signer, material) do
    case signer_kind do
      "identity" ->
        Assertions.assert_literal!(
          material["owner_id"],
          signer["user_id"],
          "signer_owner_id_mismatch"
        )

      "device" ->
        Assertions.assert_literal!(
          material["owner_id"],
          signer["device_id"],
          "signer_owner_id_mismatch"
        )

      "share_participant_device" ->
        Assertions.assert_literal!(
          material["owner_id"],
          signer["share_participant_device_id"],
          "signer_owner_id_mismatch"
        )

      "invitation_redeem_authority" ->
        Assertions.assert_literal!(
          material["owner_id"],
          signer["invitation_id"],
          "signer_owner_id_mismatch"
        )
    end
  end

  @spec event_signature_checkpoint_payload(map(), [map()], map(), map(), map()) :: map()
  def event_signature_checkpoint_payload(
        %{"event_type" => event_type},
        signatures,
        replay_payload,
        checkpoint_payload,
        authorized_share_participant_keys
      )
      when event_type in [
             "document_update_accepted",
             "document_write_session_admitted",
             "document_snapshot_accepted"
           ],
      do:
        document_event_signature_checkpoint_payload(
          signatures,
          replay_payload,
          checkpoint_payload,
          authorized_share_participant_keys
        )

  def event_signature_checkpoint_payload(
        _payload,
        _signatures,
        replay_payload,
        _checkpoint_payload,
        _authorized_share_participant_keys
      ),
      do: replay_payload

  @spec document_event_signature_checkpoint_payload([map()], map(), map(), map()) :: map()
  def document_event_signature_checkpoint_payload(
        signatures,
        replay_payload,
        checkpoint_payload,
        authorized_share_participant_keys
      ) do
    case State.share_participant_signer(signatures) do
      nil ->
        checkpoint_payload

      signer ->
        signing_key_id = signer["signing_key_id"]

        if Enum.any?(replay_payload["share_participant_keys"], &(&1["key_id"] == signing_key_id)) do
          replay_payload
        else
          entry =
            State.authorized_share_participant_key_entry!(
              authorized_share_participant_keys,
              signing_key_id
            )

          Assertions.assert_literal!(
            State.share_participant_key_entry_by_id!(checkpoint_payload, signing_key_id),
            entry,
            "share_participant_key_entry_unauthorized"
          )

          State.update_key_entries!(replay_payload, "share_participant_keys", entry)
        end
    end
  end
end
