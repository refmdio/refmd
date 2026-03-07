defmodule RefMD.Accounts do
  @moduledoc """
  The Accounts context. Manages users, sessions, and devices.
  """

  import Ecto.Query
  alias RefMD.Repo
  alias RefMD.Accounts.{User, UserSettings, Session, Device, PendingDevice}
end
