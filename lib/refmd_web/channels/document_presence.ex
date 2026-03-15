defmodule RefMDWeb.DocumentPresence do
  @moduledoc """
  Presence tracking for document channels.
  Used for per-user per-document connection cap enforcement (cluster-wide best-effort).
  """

  use Phoenix.Presence,
    otp_app: :refmd,
    pubsub_server: RefMD.PubSub
end
