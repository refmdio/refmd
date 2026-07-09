defmodule RefMDWeb.Http.DBSC do
  @moduledoc false

  import Plug.Conn

  alias RefMD.Auth.DBSC

  @registration_header "secure-session-registration"
  @challenge_header "secure-session-challenge"

  def put_registration_header(conn, session_kind, session) when is_map(session) do
    session_kind = normalize_session_kind(session_kind)

    case DBSC.registration_header(
           session_kind,
           session.id,
           DBSC.registration_path(session_kind)
         ) do
      {:ok, header} -> prepend_resp_headers(conn, [{@registration_header, header}])
      _ -> conn
    end
  end

  def put_registration_header(conn, _session_kind, _session), do: conn

  def put_challenge_header(conn, binding) do
    put_resp_header(conn, @challenge_header, DBSC.challenge_header(binding))
  end

  def origin(conn) do
    port =
      case {conn.scheme, conn.port} do
        {:http, 80} -> ""
        {:https, 443} -> ""
        {_scheme, port} -> ":#{port}"
      end

    "#{conn.scheme}://#{conn.host}#{port}"
  end

  defp normalize_session_kind(:user), do: "user"
  defp normalize_session_kind(:share_participant), do: "share_participant"
  defp normalize_session_kind(:mount), do: "mount"
  defp normalize_session_kind(session_kind), do: session_kind
end
