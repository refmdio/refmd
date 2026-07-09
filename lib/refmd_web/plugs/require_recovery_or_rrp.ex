defmodule RefMDWeb.Plugs.RequireRecoveryOrRrp do
  @moduledoc """
  Plug that exempts recovery sessions from RRP verification.

  Recovery sessions (is_recovery=true) bypass RRP because the device
  is not yet registered in the devices table (chicken-and-egg problem).
  Security is maintained via double Identity signature verification.

  Non-recovery sessions delegate to RequireRrp.
  """

  alias RefMDWeb.Plugs.RequireRrp

  def init(opts), do: opts

  def call(conn, opts) do
    session = conn.assigns.current_session

    if session.is_recovery do
      conn
    else
      RequireRrp.call(conn, opts)
    end
  end
end
