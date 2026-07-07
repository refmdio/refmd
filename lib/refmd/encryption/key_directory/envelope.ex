defmodule RefMD.Encryption.KeyDirectory.Envelope do
  @moduledoc false

  alias RefMD.Encryption.KeyDirectory.{Assertions, Event, Payload}

  def payload!(%{"payload" => payload}, kind) when is_map(payload) do
    case kind do
      :event -> Payload.assert_event_payload!(payload)
      :checkpoint -> Payload.assert_checkpoint_payload!(payload)
    end

    payload
  end

  def payload!(_, :event), do: raise(ArgumentError, "event_envelope_payload_invalid")

  def payload!(_, :checkpoint),
    do: raise(ArgumentError, "checkpoint_envelope_payload_invalid")

  def signatures!(%{"signatures" => signatures})
      when is_list(signatures) and signatures != [] do
    signatures
  end

  def signatures!(_), do: raise(ArgumentError, "key_directory_signatures_required")

  def event_head!([%Event{} | _] = events) do
    head = List.last(events)

    %{
      "head_sequence" => head.sequence,
      "head_hash" => head.event_hash
    }
  end

  def event_head!(_), do: raise(ArgumentError, "initial_event_head_required")

  def verified_event_head!([%{} | _] = events) do
    head = List.last(events)

    %{
      "head_sequence" => head.sequence,
      "head_hash" => head.event_hash
    }
  end

  def verified_event_head!(_), do: raise(ArgumentError, "event_replay_required")

  def assert_event_chain_link!(%{"sequence" => 1}, nil), do: :ok

  def assert_event_chain_link!(
        %{"sequence" => sequence, "previous_event_hash" => previous},
        expected
      )
      when sequence > 1 and is_binary(expected) do
    Assertions.assert_literal!(previous, expected, "event_previous_hash_mismatch")
  end

  def assert_event_chain_link!(_, _), do: raise(ArgumentError, "event_chain_invalid")
end
