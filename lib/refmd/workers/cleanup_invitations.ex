defmodule RefMD.Workers.CleanupInvitations do
  @moduledoc """
  Removes expired workspace and guest invitations.
  """

  use Oban.Worker, queue: :default

  alias RefMD.Workspaces

  @impl Oban.Worker
  def perform(_job) do
    Workspaces.cleanup_expired_invitations()
    :ok
  end
end
