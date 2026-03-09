defmodule RefMDWeb.DeviceEventsController do
  use RefMDWeb, :controller

  alias Phoenix.PubSub
  alias RefMD.Accounts

  @heartbeat_interval 30_000

  @spec existing_device_events(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def existing_device_events(conn, _params) do
    # Only existing (device-bound) sessions may subscribe (device.md: SSE endpoints)
    if conn.assigns.device_verified do
      user_id = conn.assigns.current_user_id

      conn =
        conn
        |> put_resp_header("content-type", "text/event-stream")
        |> put_resp_header("cache-control", "no-cache")
        |> put_resp_header("connection", "keep-alive")
        |> send_chunked(200)

      PubSub.subscribe(RefMD.PubSub, "device_events:user:#{user_id}")

      heartbeat_ref = Process.send_after(self(), :heartbeat, @heartbeat_interval)
      loop(conn, heartbeat_ref)
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "device_not_bound"})
    end
  end

  @spec pending_device_events(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def pending_device_events(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id

    # Verify the pending device belongs to this user, or was recently approved (device.md: SSE endpoints)
    authorized =
      Accounts.user_owns_pending_device?(user_id, device_id) or
        Accounts.user_owns_active_device?(user_id, device_id)

    if authorized do
      conn =
        conn
        |> put_resp_header("content-type", "text/event-stream")
        |> put_resp_header("cache-control", "no-cache")
        |> put_resp_header("connection", "keep-alive")
        |> send_chunked(200)

      PubSub.subscribe(RefMD.PubSub, "device_events:pending:#{user_id}:#{device_id}")

      expiry_ref = schedule_pending_expiry(user_id, device_id)

      heartbeat_ref = Process.send_after(self(), :heartbeat, @heartbeat_interval)
      loop(conn, heartbeat_ref, expiry_ref)
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "device_not_found"})
    end
  end

  defp loop(conn, heartbeat_ref, expiry_ref \\ nil) do
    receive do
      {:sse_event, event_type, data} ->
        handle_sse_event(conn, heartbeat_ref, expiry_ref, event_type, data)

      {:pending_expired, device_id} ->
        handle_terminal_event(conn, heartbeat_ref, "expired", %{device_id: device_id})

      {:pending_approved_late, device_id} ->
        handle_terminal_event(conn, heartbeat_ref, "pending_approved", %{device_id: device_id})

      :heartbeat ->
        handle_heartbeat(conn, heartbeat_ref, expiry_ref)
    end
  end

  defp handle_sse_event(conn, heartbeat_ref, expiry_ref, event_type, data) do
    case Plug.Conn.chunk(conn, "event: #{event_type}\ndata: #{Jason.encode!(data)}\n\n") do
      {:ok, conn} ->
        loop(conn, heartbeat_ref, expiry_ref)

      {:error, _} ->
        Process.cancel_timer(heartbeat_ref)
        if expiry_ref, do: Process.cancel_timer(expiry_ref)
        conn
    end
  end

  defp handle_terminal_event(conn, heartbeat_ref, event_type, data) do
    Process.cancel_timer(heartbeat_ref)

    case Plug.Conn.chunk(conn, "event: #{event_type}\ndata: #{Jason.encode!(data)}\n\n") do
      {:ok, conn} -> conn
      {:error, _} -> conn
    end
  end

  defp handle_heartbeat(conn, _heartbeat_ref, expiry_ref) do
    case Plug.Conn.chunk(conn, ":heartbeat\n\n") do
      {:ok, conn} ->
        new_ref = Process.send_after(self(), :heartbeat, @heartbeat_interval)
        loop(conn, new_ref, expiry_ref)

      {:error, _} ->
        if expiry_ref, do: Process.cancel_timer(expiry_ref)
        conn
    end
  end

  defp schedule_pending_expiry(user_id, device_id) do
    case Accounts.get_valid_pending_device(device_id) do
      %{expires_at: expires_at} ->
        ms = max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)
        Process.send_after(self(), {:pending_expired, device_id}, ms)

      nil ->
        resolve_missing_pending_device(user_id, device_id)
    end
  end

  defp resolve_missing_pending_device(user_id, device_id) do
    cond do
      RefMD.Encryption.get_device_encrypted_umk(user_id, device_id) != nil ->
        Process.send_after(self(), {:pending_approved_late, device_id}, 0)

      Accounts.device_exists?(device_id) ->
        nil

      true ->
        Process.send_after(self(), {:pending_expired, device_id}, 0)
    end
  end

  # Broadcasting helpers called from other controllers

  @spec broadcast_pending_device_created(Ecto.UUID.t(), RefMD.Accounts.PendingDevice.t()) ::
          :ok | {:error, term()}
  def broadcast_pending_device_created(user_id, pending_device) do
    PubSub.broadcast(RefMD.PubSub, "device_events:user:#{user_id}", {
      :sse_event,
      "pending_device_created",
      %{
        device_id: pending_device.id,
        name: pending_device.name,
        device_type: pending_device.device_type
      }
    })
  end

  @spec broadcast_pending_approved(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  def broadcast_pending_approved(user_id, device_id) do
    PubSub.broadcast(RefMD.PubSub, "device_events:pending:#{user_id}:#{device_id}", {
      :sse_event,
      "pending_approved",
      %{device_id: device_id}
    })
  end

  @spec broadcast_pending_device_removed(Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, term()}
  def broadcast_pending_device_removed(user_id, device_id) do
    PubSub.broadcast(RefMD.PubSub, "device_events:user:#{user_id}", {
      :sse_event,
      "pending_device_removed",
      %{device_id: device_id}
    })
  end

  @spec broadcast_pending_rejected(Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, term()}
  def broadcast_pending_rejected(user_id, device_id) do
    PubSub.broadcast(
      RefMD.PubSub,
      "device_events:pending:#{user_id}:#{device_id}",
      {:sse_event, "pending_rejected", %{device_id: device_id}}
    )
  end

  @spec broadcast_trust_transfer_nonce_ready(Ecto.UUID.t(), Ecto.UUID.t(), binary()) ::
          :ok | {:error, term()}
  def broadcast_trust_transfer_nonce_ready(user_id, new_device_id, nonce) do
    PubSub.broadcast(RefMD.PubSub, "device_events:user:#{user_id}", {
      :sse_event,
      "trust_transfer_nonce_ready",
      %{
        new_device_id: new_device_id,
        nonce: Base.url_encode64(nonce, padding: false)
      }
    })
  end
end
