defmodule RefMD.Workers.CleanupInvitations do
  @moduledoc """
  Periodic cleanup of invitations.

  - Physical deletion of revoked invitations 90 days after revocation
  - Physical deletion of expired unused invitations after expiry
  - Physical deletion of used invitations after expiry
  """

  use Oban.Worker, queue: :default

  import Ecto.Query
  alias RefMD.Repo
  alias RefMD.Workspaces.WorkspaceInvitation

  @gc_days 90

  @impl Oban.Worker
  def perform(_job) do
    now = DateTime.utc_now()
    revoked_cutoff = DateTime.add(now, -@gc_days * 86_400)

    {revoked_count, _} =
      from(i in WorkspaceInvitation,
        where: not is_nil(i.revoked_at) and i.revoked_at < ^revoked_cutoff
      )
      |> Repo.delete_all()

    {expired_count, _} =
      from(i in WorkspaceInvitation,
        where: i.expires_at < ^now and i.is_used == false and is_nil(i.revoked_at)
      )
      |> Repo.delete_all()

    used_cutoff = DateTime.add(now, -@gc_days * 86_400)

    {used_count, _} =
      from(i in WorkspaceInvitation,
        where: i.is_used == true and i.expires_at < ^used_cutoff
      )
      |> Repo.delete_all()

    total = revoked_count + expired_count + used_count

    if total > 0 do
      require Logger

      Logger.info(
        "Cleanup: #{total} invitations (#{revoked_count} revoked, #{expired_count} expired, #{used_count} used)"
      )
    end

    :ok
  end
end
