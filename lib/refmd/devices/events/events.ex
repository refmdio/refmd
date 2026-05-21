defmodule RefMD.Devices.Events do
  @moduledoc false

  alias Phoenix.PubSub

  @type event_name :: String.t()
  @type payload :: map()

  @spec subscribe_user(Ecto.UUID.t()) :: :ok | {:error, term()}
  def subscribe_user(user_id) do
    PubSub.subscribe(RefMD.PubSub, user_topic(user_id))
  end

  @spec subscribe_pending(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  def subscribe_pending(user_id, device_id) do
    PubSub.subscribe(RefMD.PubSub, pending_topic(user_id, device_id))
  end

  @spec broadcast_device_registration_created(Ecto.UUID.t(), RefMD.Devices.DeviceRegistration.t()) ::
          :ok | {:error, term()}
  def broadcast_device_registration_created(user_id, device_registration) do
    broadcast_user(user_id, "pending_device_created", %{
      device_id: device_registration.id,
      name: device_registration.name,
      device_type: device_registration.device_type
    })
  end

  @spec broadcast_registration_approved(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  def broadcast_registration_approved(user_id, device_id) do
    broadcast_pending(user_id, device_id, "pending_approved", %{device_id: device_id})
  end

  @spec broadcast_device_registration_removed(Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, term()}
  def broadcast_device_registration_removed(user_id, device_id) do
    broadcast_user(user_id, "pending_device_removed", %{device_id: device_id})
  end

  @spec broadcast_registration_rejected(Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, term()}
  def broadcast_registration_rejected(user_id, device_id) do
    broadcast_pending(user_id, device_id, "pending_rejected", %{device_id: device_id})
  end

  @spec broadcast_kek_rotation_needed(Ecto.UUID.t(), Ecto.UUID.t(), non_neg_integer()) ::
          :ok | {:error, term()}
  def broadcast_kek_rotation_needed(user_id, workspace_id, current_kek_version) do
    broadcast_user(user_id, "kek_rotation_needed", %{
      workspace_id: workspace_id,
      current_kek_version: current_kek_version
    })
  end

  defp broadcast_user(user_id, event, payload) do
    PubSub.broadcast(RefMD.PubSub, user_topic(user_id), {:device_event, event, payload})
  end

  @spec broadcast_pending(Ecto.UUID.t(), Ecto.UUID.t(), event_name(), payload()) ::
          :ok | {:error, term()}
  def broadcast_pending(user_id, device_id, event, payload) do
    PubSub.broadcast(RefMD.PubSub, pending_topic(user_id, device_id), {
      :device_event,
      event,
      payload
    })
  end

  defp user_topic(user_id), do: "device_events:user:#{user_id}"
  defp pending_topic(user_id, device_id), do: "device_events:pending:#{user_id}:#{device_id}"
end
