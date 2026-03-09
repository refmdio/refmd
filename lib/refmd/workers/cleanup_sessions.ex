defmodule RefMD.Workers.CleanupSessions do
  @moduledoc """
  Periodic cleanup of expired sessions.
  """

  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(_job) do
    {count, _} = RefMD.Accounts.delete_expired_sessions()

    if count > 0 do
      require Logger
      Logger.info("Cleanup: #{count} expired sessions")
    end

    :ok
  end
end
