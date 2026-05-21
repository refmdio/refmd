defmodule RefMDWeb.UserSocket do
  @moduledoc """
  Phoenix Socket for authenticated WebSocket connections.
  Authentication via short-lived ws-token obtained from POST /api/auth/ws-token.
  """

  use Phoenix.Socket

  alias RefMD.Auth
  alias RefMD.Sharing
  alias RefMDWeb.Channels.SocketAuth

  channel "document:*", RefMDWeb.DocumentChannel
  channel "devices:*", RefMDWeb.DeviceEventsChannel

  @spec connect(map(), Phoenix.Socket.t(), map()) :: {:ok, Phoenix.Socket.t()} | :error
  def connect(%{"token" => token}, socket, _connect_info) when is_binary(token) do
    if origin_required_but_missing?(), do: throw(:origin_required)

    case Auth.verify_ws_token(token) do
      {:ok, user_id, session} ->
        socket =
          socket
          |> assign(:current_user_id, user_id)
          |> assign(:current_session, session)

        {:ok, socket}

      _ ->
        connect_share_participant(token, socket)
    end
  catch
    :origin_required -> :error
  end

  def connect(_params, _socket, _connect_info), do: :error

  @spec id(Phoenix.Socket.t()) :: String.t()
  def id(socket) do
    case socket.assigns[:session_kind] do
      :share_participant -> "share_socket:#{socket.assigns.current_user_id}"
      _ -> "user_socket:#{socket.assigns.current_user_id}"
    end
  end

  defp connect_share_participant(token, socket) do
    case Sharing.verify_ws_token(token) do
      {:ok, principal_id, session} ->
        socket =
          socket
          |> assign(:current_user_id, principal_id)
          |> assign(:current_session, session)
          |> assign(:current_share_id, session.share_id)
          |> assign(:share_participant_grant, session.grant)
          |> assign(:share_participant_principal_id, principal_id)
          |> assign(:session_kind, :share_participant)

        {:ok, socket}

      _ ->
        :error
    end
  end

  defp origin_required_but_missing? do
    not SocketAuth.origin_present?() and
      Application.get_env(:refmd, :samesite_mode, "lax") == "none"
  end
end
