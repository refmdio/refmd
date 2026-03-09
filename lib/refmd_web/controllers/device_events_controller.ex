defmodule RefMDWeb.DeviceEventsController do
  use RefMDWeb, :controller

  alias Phoenix.PubSub
  alias RefMD.Accounts

  @heartbeat_interval 30_000

  def existing_device_events(conn, _params) do
    # Only existing (device-bound) sessions may subscribe (device.md: SSE endpoints)
    if not conn.assigns.device_verified do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "device_not_bound"})
    else
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
    end
  end

  def pending_device_events(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id

    # Verify the pending device belongs to this user, or was recently approved (device.md: SSE endpoints)
    authorized =
      Accounts.user_owns_pending_device?(user_id, device_id) or
        Accounts.user_owns_active_device?(user_id, device_id)

    if not authorized do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "device_not_found"})
    else
      conn =
        conn
        |> put_resp_header("content-type", "text/event-stream")
        |> put_resp_header("cache-control", "no-cache")
        |> put_resp_header("connection", "keep-alive")
        |> send_chunked(200)

      PubSub.subscribe(RefMD.PubSub, "device_events:pending:#{user_id}:#{device_id}")

      expiry_ref =
        case Accounts.get_valid_pending_device(device_id) do
          %{expires_at: expires_at} ->
            ms = max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)
            Process.send_after(self(), {:pending_expired, device_id}, ms)

          nil ->
            # Pending device gone: only report approved when UMK has been distributed
            cond do
              RefMD.Encryption.get_device_encrypted_umk(user_id, device_id) != nil ->
                Process.send_after(self(), {:pending_approved_late, device_id}, 0)

              Accounts.device_exists?(device_id) ->
                # Approved but UMK not yet distributed; wait for PubSub broadcast
                nil

              true ->
                Process.send_after(self(), {:pending_expired, device_id}, 0)
            end
        end

      heartbeat_ref = Process.send_after(self(), :heartbeat, @heartbeat_interval)
      loop(conn, heartbeat_ref, expiry_ref)
    end
  end

  defp loop(conn, heartbeat_ref, expiry_ref \\ nil) do
    receive do
      {:sse_event, event_type, data} ->
        case Plug.Conn.chunk(conn, "event: #{event_type}\ndata: #{Jason.encode!(data)}\n\n") do
          {:ok, conn} -> loop(conn, heartbeat_ref, expiry_ref)
          {:error, _} ->
            Process.cancel_timer(heartbeat_ref)
            if expiry_ref, do: Process.cancel_timer(expiry_ref)
            conn
        end

      {:pending_expired, device_id} ->
        data = %{device_id: device_id}
        Process.cancel_timer(heartbeat_ref)
        case Plug.Conn.chunk(conn, "event: expired\ndata: #{Jason.encode!(data)}\n\n") do
          {:ok, conn} -> conn
          {:error, _} -> conn
        end

      {:pending_approved_late, device_id} ->
        data = %{device_id: device_id}
        Process.cancel_timer(heartbeat_ref)
        case Plug.Conn.chunk(conn, "event: pending_approved\ndata: #{Jason.encode!(data)}\n\n") do
          {:ok, conn} -> conn
          {:error, _} -> conn
        end

      :heartbeat ->
        case Plug.Conn.chunk(conn, ":heartbeat\n\n") do
          {:ok, conn} ->
            new_ref = Process.send_after(self(), :heartbeat, @heartbeat_interval)
            loop(conn, new_ref, expiry_ref)

          {:error, _} ->
            if expiry_ref, do: Process.cancel_timer(expiry_ref)
            conn
        end
    end
  end

  # Broadcasting helpers called from other controllers

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

  def broadcast_pending_approved(user_id, device_id) do
    PubSub.broadcast(RefMD.PubSub, "device_events:pending:#{user_id}:#{device_id}", {
      :sse_event,
      "pending_approved",
      %{device_id: device_id}
    })
  end

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
