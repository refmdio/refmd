defmodule RefMD.Security.MutationOutboxDispatcher do
  @moduledoc false

  alias RefMD.Crypto.JCS
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.Notification

  def deliver("security_notification_delivery", target, payload, _idempotency_key) do
    with %Notification{} = notification <- Repo.get(Notification, target["notification_id"]),
         true <- notification.recipient_kind == target["recipient_kind"],
         true <- notification.recipient_id == target["recipient_id"],
         true <-
           JCS.canonical_bytes!(Security.notification_outbox_payload(notification)) ==
             JCS.canonical_bytes!(payload) do
      Security.broadcast_notification(notification)
      :ok
    else
      _ -> {:error, :security_notification_delivery_invalid}
    end
  end

  def deliver("pubsub_broadcast", target, payload, idempotency_key) do
    if payload["audit_event_id"] == target["audit_event_id"] do
      Phoenix.PubSub.broadcast(
        RefMD.PubSub,
        target["topic"],
        {:security_mutation, payload, idempotency_key}
      )

      :ok
    else
      {:error, :pubsub_audit_event_mismatch}
    end
  end

  def deliver(effect_kind, target, payload, idempotency_key) do
    adapters = Application.get_env(:refmd, :security_mutation_effect_adapters, %{})

    case Map.get(adapters, effect_kind) do
      module when is_atom(module) and not is_nil(module) ->
        module.deliver(target, payload, idempotency_key)

      nil ->
        {:error, :security_mutation_effect_adapter_missing}
    end
  end
end
