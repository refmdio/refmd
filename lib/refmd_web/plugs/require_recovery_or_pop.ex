defmodule RefMDWeb.Plugs.RequireRecoveryOrPoP do
  @moduledoc """
  Plug that exempts recovery sessions from PoP verification.

  Recovery sessions (is_recovery=true) bypass PoP because the device
  is not yet registered in the devices table (chicken-and-egg problem).
  Security is maintained via double Identity signature verification.

  Non-recovery sessions delegate to RequirePoP.
  """

  alias RefMDWeb.Plugs.RequirePoP

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, opts) do
    session = conn.assigns.current_session

    if session.is_recovery do
      conn
    else
      RequirePoP.call(conn, opts)
    end
  end
end
