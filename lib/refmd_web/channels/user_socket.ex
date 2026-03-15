defmodule RefMDWeb.UserSocket do
  @moduledoc """
  Phoenix Socket for authenticated WebSocket connections.
  Session token is extracted from the HttpOnly _refmd_session cookie.
  """

  use Phoenix.Socket

  alias RefMD.Auth

  channel "document:*", RefMDWeb.DocumentChannel

  @spec connect(map(), Phoenix.Socket.t(), map()) :: {:ok, Phoenix.Socket.t()} | :error
  def connect(_params, socket, connect_info) do
    with :ok <- RefMDWeb.SocketAuth.verify_origin_policy(connect_info[:origin]),
         {:ok, user_id, session} <- authenticate(connect_info) do
      socket =
        socket
        |> assign(:current_user_id, user_id)
        |> assign(:current_session, session)

      {:ok, socket}
    else
      _ -> :error
    end
  end

  @spec id(Phoenix.Socket.t()) :: String.t()
  def id(socket), do: "user_socket:#{socket.assigns.current_user_id}"

  defp authenticate(connect_info) do
    with token when is_binary(token) <- connect_info.session_token,
         {:ok, session} <- Auth.get_valid_session_by_token_base64(token) do
      Auth.touch_session(session.id)
      {:ok, session.user_id, session}
    else
      _ -> :error
    end
  end
end
