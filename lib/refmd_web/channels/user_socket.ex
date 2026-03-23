defmodule RefMDWeb.UserSocket do
  @moduledoc """
  Phoenix Socket for authenticated WebSocket connections.
  Authentication via short-lived ws-token obtained from POST /api/auth/ws-token.
  """

  use Phoenix.Socket

  alias RefMD.Auth
  alias RefMDWeb.SocketAuth

  channel "document:*", RefMDWeb.DocumentChannel

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
        :error
    end
  catch
    :origin_required -> :error
  end

  def connect(_params, _socket, _connect_info), do: :error

  @spec id(Phoenix.Socket.t()) :: String.t()
  def id(socket), do: "user_socket:#{socket.assigns.current_user_id}"

  defp origin_required_but_missing? do
    not SocketAuth.origin_present?() and
      Application.get_env(:refmd, :samesite_mode, "lax") == "none"
  end
end
