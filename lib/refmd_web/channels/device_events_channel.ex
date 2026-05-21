defmodule RefMDWeb.DeviceEventsChannel do
  @moduledoc """
  Phoenix Channel for device registration events.
  """

  use Phoenix.Channel

  alias RefMD.Devices

  @terminal_pending_events ~w(pending_approved pending_rejected expired)

  @impl true
  def join("devices:" <> _rest, _params, %{assigns: %{session_kind: :share_participant}}) do
    {:error, %{reason: "user_session_required"}}
  end

  def join("devices:user", _params, socket) do
    if existing_device_session?(socket.assigns.current_session) do
      :ok = Devices.subscribe_user(socket.assigns.current_user_id)
      {:ok, %{}, assign(socket, :device_events_scope, :user)}
    else
      {:error, %{reason: "existing_device_required"}}
    end
  end

  def join("devices:registration:" <> raw_device_id, _params, socket) do
    user_id = socket.assigns.current_user_id

    with {:ok, device_id} <- Ecto.UUID.cast(raw_device_id),
         true <- pending_device_authorized?(user_id, device_id) do
      :ok = Devices.subscribe_pending(user_id, device_id)
      expiry_ref = schedule_pending_expiry(user_id, device_id)

      socket =
        socket
        |> assign(:device_events_scope, :registration)
        |> assign(:device_id, device_id)
        |> assign(:pending_expiry_ref, expiry_ref)

      {:ok, %{}, socket}
    else
      _ -> {:error, %{reason: "device_not_found"}}
    end
  end

  @impl true
  def handle_info({:device_event, event, payload}, socket) do
    push(socket, event, payload)

    if socket.assigns[:device_events_scope] == :registration and event in @terminal_pending_events do
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:pending_expired, device_id}, socket) do
    push(socket, "expired", %{device_id: device_id})
    {:stop, :normal, socket}
  end

  def handle_info({:pending_approved_late, device_id}, socket) do
    push(socket, "pending_approved", %{device_id: device_id})
    {:stop, :normal, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    if ref = socket.assigns[:pending_expiry_ref] do
      Process.cancel_timer(ref)
    end

    :ok
  end

  defp existing_device_session?(%{device_id: device_id, is_recovery: is_recovery}) do
    device_id != nil and not is_recovery
  end

  defp existing_device_session?(_session), do: false

  defp pending_device_authorized?(user_id, device_id) do
    Devices.user_owns_device_registration?(user_id, device_id) or
      Devices.user_owns_active_device?(user_id, device_id)
  end

  defp schedule_pending_expiry(user_id, device_id) do
    case Devices.get_valid_device_registration(device_id) do
      %{expires_at: expires_at} ->
        ms = max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)
        Process.send_after(self(), {:pending_expired, device_id}, ms)

      nil ->
        resolve_missing_device_registration(user_id, device_id)
    end
  end

  defp resolve_missing_device_registration(user_id, device_id) do
    cond do
      Devices.get_device_encrypted_umk(user_id, device_id) != nil ->
        Process.send_after(self(), {:pending_approved_late, device_id}, 0)

      Devices.get_device(device_id) != nil ->
        nil

      true ->
        Process.send_after(self(), {:pending_expired, device_id}, 0)
    end
  end
end
