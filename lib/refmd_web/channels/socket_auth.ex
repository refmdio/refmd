defmodule RefMDWeb.Channels.SocketAuth do
  @moduledoc """
  WebSocket Origin verification for CSWSH protection.
  check_origin/1 is used as an MFA callback by Phoenix Socket transport.
  origin_present?/0 provides fail-close for missing Origin in SameSite=None deployments.
  """

  def check_origin(%URI{} = origin) do
    Process.put(:ws_origin_present, true)
    allowed = Application.get_env(:refmd, :cors_origins, [])

    case allowed do
      [] ->
        samesite = Application.get_env(:refmd, :samesite_mode, "lax")
        samesite != "none"

      origins ->
        URI.to_string(%{origin | path: nil, query: nil, fragment: nil}) in origins
    end
  end

  def origin_present?, do: Process.get(:ws_origin_present, false)
end
