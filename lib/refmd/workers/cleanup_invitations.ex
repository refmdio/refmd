defmodule RefMD.Workers.CleanupInvitations do
  @moduledoc """
  Workspace and guest invitations are not persisted by this worker.
  """

  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(_job), do: :ok
end
