defmodule RefMD.Workers.KekRotationReminder do
  @moduledoc """
  Periodic check for incomplete KEK rotations.
  Broadcasts device notifications to workspace members via PubSub.
  """

  use Oban.Worker, queue: :default

  alias RefMD.Devices

  require Logger

  @impl Oban.Worker
  def perform(_job) do
    pending = RefMD.Workspaces.list_workspaces_needing_kek_rotation()

    if pending != [] do
      Logger.warning(
        "KEK rotation pending for #{length(pending)} workspace(s): " <>
          Enum.map_join(pending, ", ", & &1.workspace_id)
      )

      Enum.each(pending, &notify_workspace_members/1)
    end

    :ok
  end

  defp notify_workspace_members(workspace) do
    user_ids = RefMD.Workspaces.list_workspace_member_user_ids(workspace.workspace_id)

    Enum.each(user_ids, fn user_id ->
      Devices.broadcast_kek_rotation_needed(
        user_id,
        workspace.workspace_id,
        workspace.current_kek_version
      )
    end)
  end
end
