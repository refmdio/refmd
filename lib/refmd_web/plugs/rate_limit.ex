defmodule RefMDWeb.Plugs.RateLimit do
  @moduledoc """
  Rate limiting plug using PlugAttack with ETS backend.
  """

  use PlugAttack

  rule "throttle by ip", conn do
    throttle(conn.remote_ip,
      period: 60_000,
      limit: 60,
      storage: {PlugAttack.Storage.Ets, RefMDWeb.Plugs.RateLimit.Storage}
    )
  end

  rule "throttle auth endpoints", conn do
    if String.starts_with?(conn.request_path, "/api/auth") do
      throttle(conn.remote_ip,
        period: 60_000,
        limit: 20,
        storage: {PlugAttack.Storage.Ets, RefMDWeb.Plugs.RateLimit.Storage}
      )
    end
  end
end
