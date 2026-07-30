defmodule RefMD.Security.MutationOutbox do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Repo
  alias RefMD.Security.MutationOutboxItem

  @protocol "refmd.security-mutation-outbox"
  @version 1
  @idempotency_protocol "refmd.security-mutation-outbox-idempotency"
  @target_keys %{
    "security_notification_delivery" => ~w(notification_id recipient_id recipient_kind),
    "pubsub_broadcast" => ~w(audit_event_id topic),
    "push_delivery" => ~w(destination_hash notification_id recipient_id),
    "email_delivery" => ~w(destination_hash notification_id recipient_id),
    "pin_gossip_transport" => ~w(recipient_device_id statement_hash),
    "security_analytics" => ~w(audit_event_id sink_id)
  }

  def build!(compound_intent_id, mutation_id, effect_kind, target, payload, available_at \\ now()) do
    assert_uuid!(compound_intent_id)
    assert_uuid!(mutation_id)
    assert_target!(effect_kind, target)

    target_bytes = JCS.canonical_bytes!(target)
    payload_bytes = JCS.canonical_bytes!(payload)
    target_hash = Hash.blake3_base64url(target_bytes)
    payload_hash = Hash.blake3_base64url(payload_bytes)

    idempotency_key =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => @idempotency_protocol,
          "version" => 1,
          "compound_intent_id" => compound_intent_id,
          "mutation_id" => mutation_id,
          "effect_kind" => effect_kind,
          "effect_target_hash" => target_hash,
          "payload_hash" => payload_hash
        })
      )

    %{
      protocol: @protocol,
      version: @version,
      compound_intent_id: compound_intent_id,
      mutation_id: mutation_id,
      effect_kind: effect_kind,
      effect_target_jcs_b64u: encode(target_bytes),
      effect_target_hash: target_hash,
      payload_jcs_b64u: encode(payload_bytes),
      payload_hash: payload_hash,
      idempotency_key: idempotency_key,
      status: "pending",
      attempt_count: 0,
      available_at: available_at,
      lease_expires_at: nil,
      delivered_at: nil
    }
  end

  def enqueue_all!(items) when is_list(items) do
    items
    |> Enum.sort_by(& &1.effect_target_hash)
    |> reject_duplicate_targets!()
    |> Enum.map(fn attrs ->
      %MutationOutboxItem{}
      |> MutationOutboxItem.changeset(attrs)
      |> Repo.insert!()
    end)
  end

  def claim_available(limit, lease_seconds, claimed_at \\ now())
      when is_integer(limit) and limit > 0 and is_integer(lease_seconds) and lease_seconds > 0 do
    lease_expires_at = DateTime.add(claimed_at, lease_seconds, :second)

    Repo.transaction(fn ->
      MutationOutboxItem
      |> where(
        [item],
        (item.status == "pending" and item.available_at <= ^claimed_at) or
          (item.status == "processing" and item.lease_expires_at <= ^claimed_at)
      )
      |> order_by([item], asc: item.available_at, asc: item.outbox_id)
      |> limit(^limit)
      |> lock("FOR UPDATE SKIP LOCKED")
      |> Repo.all()
      |> Enum.map(fn item ->
        item
        |> Ecto.Changeset.change(%{
          status: "processing",
          attempt_count: item.attempt_count + 1,
          lease_expires_at: lease_expires_at
        })
        |> Repo.update!()
      end)
    end)
  end

  def mark_delivered!(%MutationOutboxItem{status: "processing"} = item, delivered_at \\ now()) do
    item
    |> Ecto.Changeset.change(%{
      status: "delivered",
      delivered_at: delivered_at,
      lease_expires_at: nil
    })
    |> Repo.update!()
  end

  def retry!(%MutationOutboxItem{status: "processing"} = item, available_at) do
    item
    |> Ecto.Changeset.change(%{
      status: "pending",
      available_at: available_at,
      lease_expires_at: nil
    })
    |> Repo.update!()
  end

  def decode_target!(item), do: decode_canonical!(item.effect_target_jcs_b64u)
  def decode_payload!(item), do: decode_canonical!(item.payload_jcs_b64u)

  def process_available(dispatch, opts \\ []) when is_function(dispatch, 4) do
    limit = Keyword.get(opts, :limit, 50)
    lease_seconds = Keyword.get(opts, :lease_seconds, 60)
    claimed_at = Keyword.get(opts, :now, now())

    {:ok, items} = claim_available(limit, lease_seconds, claimed_at)

    Enum.map(items, fn item ->
      result =
        dispatch.(
          item.effect_kind,
          decode_target!(item),
          decode_payload!(item),
          item.idempotency_key
        )

      case result do
        :ok ->
          {:delivered, mark_delivered!(item, claimed_at)}

        {:error, reason} ->
          retry_at = DateTime.add(claimed_at, retry_delay_seconds(item.attempt_count), :second)
          {:retry, retry!(item, retry_at), reason}

        _ ->
          raise ArgumentError, "outbox_dispatch_result_invalid"
      end
    end)
  end

  defp assert_target!(effect_kind, target) do
    expected_keys =
      Map.get(@target_keys, effect_kind) || raise ArgumentError, "outbox_effect_kind_invalid"

    unless is_map(target) and Enum.sort(Map.keys(target)) == expected_keys and
             Enum.all?(target, fn {_key, value} -> not is_nil(value) and value != "" end) do
      raise ArgumentError, "outbox_effect_target_invalid"
    end
  end

  defp reject_duplicate_targets!(items) do
    keys =
      Enum.map(
        items,
        &{&1.compound_intent_id, &1.mutation_id, &1.effect_kind, &1.effect_target_hash}
      )

    if length(keys) != length(Enum.uniq(keys)),
      do: raise(ArgumentError, "outbox_effect_target_duplicate")

    items
  end

  defp decode_canonical!(encoded) do
    bytes = Base.url_decode64!(encoded, padding: false)
    value = JCS.parse_json_strict!(bytes)

    unless JCS.canonical_bytes!(value) == bytes,
      do: raise(ArgumentError, "outbox_jcs_noncanonical")

    value
  end

  defp assert_uuid!(value) do
    unless match?({:ok, _}, Ecto.UUID.cast(value)),
      do: raise(ArgumentError, "outbox_uuid_invalid")
  end

  defp encode(bytes), do: Base.url_encode64(bytes, padding: false)
  defp retry_delay_seconds(attempt_count), do: min(Integer.pow(2, attempt_count), 3_600)
  defp now, do: DateTime.utc_now() |> DateTime.truncate(:microsecond)
end
