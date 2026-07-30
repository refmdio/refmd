defmodule RefMD.Security.MutationOutboxTest do
  use RefMD.DataCase, async: false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Repo
  alias RefMD.Security.{MutationOutbox, MutationOutboxItem}

  test "builds, claims, retries, and delivers one canonical effect" do
    compound_intent_id = Ecto.UUID.generate()
    mutation_id = Ecto.UUID.generate()
    notification_id = Ecto.UUID.generate()
    recipient_id = Ecto.UUID.generate()
    available_at = ~U[2026-07-16 00:00:00.000000Z]

    target = %{
      "notification_id" => notification_id,
      "recipient_kind" => "user",
      "recipient_id" => recipient_id
    }

    payload = %{"notification_id" => notification_id, "type" => "device.approved"}

    attrs =
      MutationOutbox.build!(
        compound_intent_id,
        mutation_id,
        "security_notification_delivery",
        target,
        payload,
        available_at
      )

    assert attrs.protocol == "refmd.security-mutation-outbox"
    assert attrs.version == 1
    assert attrs.status == "pending"
    assert attrs.attempt_count == 0
    assert attrs.effect_target_hash == canonical_hash(target)
    assert attrs.payload_hash == canonical_hash(payload)

    [inserted] = MutationOutbox.enqueue_all!([attrs])
    assert MutationOutbox.decode_target!(inserted) == target
    assert MutationOutbox.decode_payload!(inserted) == payload

    assert {:ok, [claimed]} = MutationOutbox.claim_available(1, 30, available_at)
    assert claimed.status == "processing"
    assert claimed.attempt_count == 1
    assert claimed.lease_expires_at == ~U[2026-07-16 00:00:30.000000Z]

    retry_at = ~U[2026-07-16 00:01:00.000000Z]
    retried = MutationOutbox.retry!(claimed, retry_at)
    assert retried.status == "pending"
    assert retried.lease_expires_at == nil

    assert {:ok, []} = MutationOutbox.claim_available(1, 30, available_at)
    assert {:ok, [reclaimed]} = MutationOutbox.claim_available(1, 30, retry_at)
    assert reclaimed.attempt_count == 2

    delivered = MutationOutbox.mark_delivered!(reclaimed, retry_at)
    assert delivered.status == "delivered"
    assert delivered.delivered_at == retry_at
    assert delivered.lease_expires_at == nil
    assert {:ok, []} = MutationOutbox.claim_available(1, 30, retry_at)
  end

  test "rejects unknown, malformed, and duplicate effect targets atomically" do
    compound_intent_id = Ecto.UUID.generate()
    mutation_id = Ecto.UUID.generate()
    now = ~U[2026-07-16 00:00:00.000000Z]

    assert_raise ArgumentError, "outbox_effect_kind_invalid", fn ->
      MutationOutbox.build!(compound_intent_id, mutation_id, "unknown", %{}, %{}, now)
    end

    assert_raise ArgumentError, "outbox_effect_target_invalid", fn ->
      MutationOutbox.build!(
        compound_intent_id,
        mutation_id,
        "pubsub_broadcast",
        %{"topic" => "security:user"},
        %{},
        now
      )
    end

    attrs =
      MutationOutbox.build!(
        compound_intent_id,
        mutation_id,
        "pubsub_broadcast",
        %{"topic" => "security:user", "audit_event_id" => Ecto.UUID.generate()},
        %{"event" => "changed"},
        now
      )

    assert_raise ArgumentError, "outbox_effect_target_duplicate", fn ->
      Repo.transaction(fn -> MutationOutbox.enqueue_all!([attrs, attrs]) end)
    end

    assert Repo.aggregate(MutationOutboxItem, :count) == 0
  end

  test "delivery failure retains the same row and idempotency key for backoff retry" do
    now = ~U[2026-07-16 00:00:00.000000Z]

    attrs =
      MutationOutbox.build!(
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        "pubsub_broadcast",
        %{"topic" => "security:user", "audit_event_id" => Ecto.UUID.generate()},
        %{"audit_event_id" => Ecto.UUID.generate()},
        now
      )

    [inserted] = MutationOutbox.enqueue_all!([attrs])

    assert [{:retry, retried, :unavailable}] =
             MutationOutbox.process_available(
               fn _kind, _target, _payload, idempotency_key ->
                 assert idempotency_key == inserted.idempotency_key
                 {:error, :unavailable}
               end,
               now: now
             )

    assert retried.outbox_id == inserted.outbox_id
    assert retried.idempotency_key == inserted.idempotency_key
    assert retried.status == "pending"
    assert retried.available_at == ~U[2026-07-16 00:00:02.000000Z]

    assert [{:delivered, delivered}] =
             MutationOutbox.process_available(
               fn _kind, _target, _payload, idempotency_key ->
                 assert idempotency_key == inserted.idempotency_key
                 :ok
               end,
               now: retried.available_at
             )

    assert delivered.outbox_id == inserted.outbox_id
    assert delivered.attempt_count == 2
  end

  defp canonical_hash(value), do: Hash.blake3_base64url(JCS.canonical_bytes!(value))
end
