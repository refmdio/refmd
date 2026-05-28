defmodule RefMDWeb.SecurityChannel do
  @moduledoc """
  Phoenix Channel for application-wide security notifications.
  """

  use Phoenix.Channel

  alias RefMD.Devices
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Workspaces
  alias RefMD.Workspaces.Workspace

  @terminal_pending_notifications ~w(
    device.registration_approved
    device.registration_rejected
    device.registration_expired
  )

  @impl true
  def join("security:" <> _rest, _params, %{assigns: %{session_kind: :share_participant}}) do
    {:error, %{reason: "user_session_required"}}
  end

  def join("security:user:" <> raw_user_id, _params, socket) do
    with true <- raw_user_id == socket.assigns.current_user_id,
         true <- existing_device_session?(socket.assigns.current_session) do
      :ok = Security.subscribe_user(socket.assigns.current_user_id)
      {:ok, %{}, assign(socket, :security_scope, :user)}
    else
      _ -> {:error, %{reason: "existing_device_required"}}
    end
  end

  def join("security:device:" <> raw_device_id, _params, socket) do
    with {:ok, device_id} <- Ecto.UUID.cast(raw_device_id),
         true <- current_device_session?(socket.assigns.current_session, device_id),
         true <- Devices.user_owns_active_device?(socket.assigns.current_user_id, device_id) do
      :ok = Security.subscribe_device(device_id)
      {:ok, %{}, assign(socket, :security_scope, :device)}
    else
      _ -> {:error, %{reason: "existing_device_required"}}
    end
  end

  def join("security:workspace:" <> raw_workspace_id, _params, socket) do
    with {:ok, workspace_id} <- Ecto.UUID.cast(raw_workspace_id),
         true <- existing_device_session?(socket.assigns.current_session),
         true <- workspace_security_authorized?(socket.assigns.current_user_id, workspace_id) do
      :ok = Security.subscribe_workspace(workspace_id)
      {:ok, %{}, assign(socket, :security_scope, :workspace)}
    else
      _ -> {:error, %{reason: "workspace_not_found"}}
    end
  end

  def join("security:pending_registration:" <> raw_registration_id, _params, socket) do
    user_id = socket.assigns.current_user_id

    with {:ok, registration_id} <- Ecto.UUID.cast(raw_registration_id),
         true <- pending_registration_authorized?(user_id, registration_id) do
      :ok = Security.subscribe_pending_registration(registration_id)
      expiry_ref = schedule_pending_expiry(user_id, registration_id)

      socket =
        socket
        |> assign(:security_scope, :pending_registration)
        |> assign(:registration_id, registration_id)
        |> assign(:pending_expiry_ref, expiry_ref)

      {:ok, %{}, socket}
    else
      _ -> {:error, %{reason: "registration_not_found"}}
    end
  end

  @impl true
  def handle_info({:security_notification, payload}, socket) do
    push(socket, "notification", payload)

    if socket.assigns[:security_scope] == :pending_registration and
         payload.type in @terminal_pending_notifications do
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:pending_expired, user_id, registration_id}, socket) do
    case Security.record_registration_expired(user_id, registration_id) do
      {:ok, _} -> {:stop, :normal, socket}
      {:error, _reason} -> {:stop, :normal, socket}
    end
  end

  def handle_info({:registration_already_approved, registration_id}, socket) do
    push(socket, "notification", %{
      type: "device.registration_approved",
      action_ref: %{device_id: registration_id}
    })

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

  defp current_device_session?(%{device_id: device_id, is_recovery: is_recovery}, device_id),
    do: not is_recovery

  defp current_device_session?(_session, _device_id), do: false

  defp pending_registration_authorized?(user_id, registration_id) do
    Devices.user_owns_device_registration?(user_id, registration_id) or
      Devices.user_owns_active_device?(user_id, registration_id)
  end

  defp workspace_security_authorized?(user_id, workspace_id) do
    case Repo.get(Workspace, workspace_id) do
      %Workspace{owner_id: ^user_id} ->
        true

      %Workspace{} ->
        Workspaces.get_member_role(workspace_id, user_id) in ["owner", "admin"]

      nil ->
        false
    end
  end

  defp schedule_pending_expiry(user_id, registration_id) do
    case Devices.get_valid_device_registration(registration_id) do
      %{expires_at: expires_at} ->
        ms = max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)
        Process.send_after(self(), {:pending_expired, user_id, registration_id}, ms)

      nil ->
        resolve_missing_registration(user_id, registration_id)
    end
  end

  defp resolve_missing_registration(user_id, registration_id) do
    cond do
      Devices.get_device_encrypted_umk(user_id, registration_id) != nil ->
        Process.send_after(self(), {:registration_already_approved, registration_id}, 0)

      Devices.get_device(registration_id) != nil ->
        nil

      true ->
        Process.send_after(self(), {:pending_expired, user_id, registration_id}, 0)
    end
  end
end
